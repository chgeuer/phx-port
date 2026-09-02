#[cfg(test)]
use crate::ingress_limits::{IngressLimits, SystemCapacity};
use crate::{
    activated_listener::{self, ListenerOrigin},
    admission::{
        AdmissionController, AdmissionRejection, PreRoutingAdmission, RelayAdmission, RelayPermit,
    },
    config_path, handoff,
    ingress_config::{
        DEFAULT_RELAY_IDLE_TIMEOUT, HostingProfile, MAX_ROUTE_DECLARATIONS, PublicIngressSnapshot,
        RouteDeclaration,
    },
    ingress_limits::{
        CERTIFICATE_PROBE_WORKERS, DaemonConfig, ROUTE_SELECTION_WORKERS, TOKIO_RUNTIME_WORKERS,
        ValidatedIngressLimits,
    },
    is_port_open, observability, port_registry, privilege,
    production_paths::{IntentOwner, ProductionPaths},
    read_config, relay, route_cache, tls_client_hello,
    worker_pool::BoundedWorkerPool,
};
use native_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as FmtWrite;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PROBES: usize = CERTIFICATE_PROBE_WORKERS;
const MAX_WAITING_CLIENTS: usize = 64;
const MAX_NEGATIVE_ROUTES: usize = 1024;
const MAX_VERIFIED_ROUTES: usize = 1024;
const MAX_ROUTE_CONFLICTS: usize = 1024;
const MAX_ROUTE_DIAGNOSTICS: usize = 64;
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const LIVENESS_INTERVAL: Duration = Duration::from_secs(1);
const TLS_REVALIDATION_INTERVAL: Duration = Duration::from_secs(30);
const TCP_FAILURE_THRESHOLD: u8 = 3;
const DEVELOPMENT_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLIC_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
const PHXP_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const ROUTE_SELECTION_QUEUE_CAPACITY: usize = MAX_WAITING_CLIENTS - ROUTE_SELECTION_WORKERS;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const OVERLOAD_EVENT_INTERVAL: Duration = Duration::from_secs(10);
const DELIVERY_EVENT_INTERVAL: Duration = Duration::from_secs(10);
const SOURCE_DIAGNOSTIC_EVENT_INTERVAL: Duration = Duration::from_secs(1);
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_IO_POLL_INTERVAL: Duration = Duration::from_millis(50);
const CONTROL_REQUEST_LIMIT: u64 = 1024;
const CONTROL_RESPONSE_LIMIT: u64 = 64 * 1024;
const CONTROL_SCHEMA_VERSION: u32 = 1;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

#[derive(Clone)]
struct IngressShutdown {
    requested: Arc<AtomicBool>,
    exiting: Arc<AtomicBool>,
    requested_tx: watch::Sender<bool>,
    drain_window: Arc<OnceLock<DrainWindow>>,
    transition: Arc<Mutex<()>>,
    drain_timeout: Duration,
}

#[derive(Clone, Copy)]
struct DrainWindow {
    started_at: Instant,
    deadline: Instant,
}

impl IngressShutdown {
    fn new(drain_timeout: Duration) -> Self {
        let (requested_tx, _) = watch::channel(false);
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            exiting: Arc::new(AtomicBool::new(false)),
            requested_tx,
            drain_window: Arc::new(OnceLock::new()),
            transition: Arc::new(Mutex::new(())),
            drain_timeout,
        }
    }

    fn request(&self) {
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.drain_window.get_or_init(|| {
            let started_at = Instant::now();
            let deadline = started_at
                .checked_add(self.drain_timeout)
                .unwrap_or(started_at);
            DrainWindow {
                started_at,
                deadline,
            }
        });
        self.requested.store(true, Ordering::Release);
        self.requested_tx.send_replace(true);
    }

    fn commit_if_running(&self, commit: impl FnOnce()) -> bool {
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_requested() {
            return false;
        }
        commit();
        true
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    fn finish(&self) {
        self.exiting.store(true, Ordering::Release);
    }

    fn is_exiting(&self) -> bool {
        self.exiting.load(Ordering::Acquire)
    }

    fn requested_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.requested)
    }

    fn drain_deadline(&self) -> Instant {
        self.drain_window().deadline
    }

    fn drain_elapsed(&self) -> Duration {
        Instant::now().saturating_duration_since(self.drain_window().started_at)
    }

    fn drain_window(&self) -> DrainWindow {
        *self.drain_window.get_or_init(|| {
            let started_at = Instant::now();
            let deadline = started_at
                .checked_add(self.drain_timeout)
                .unwrap_or(started_at);
            DrainWindow {
                started_at,
                deadline,
            }
        })
    }

    async fn wait_requested(&self) {
        let mut requested = self.requested_tx.subscribe();
        while !*requested.borrow_and_update() {
            if requested.changed().await.is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        self.requested_tx.receiver_count()
    }
}

fn saturating_atomic_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Backend {
    project: String,
    role: String,
    port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CertificateProof {
    fingerprint: String,
    not_after_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CertificateExpiryState {
    Valid,
    Warning30Days,
    Warning14Days,
    Warning7Days,
    Warning1Day,
    Expired,
}

impl CertificateExpiryState {
    fn at(not_after_unix_seconds: u64, now_unix_seconds: u64) -> Self {
        if now_unix_seconds >= not_after_unix_seconds {
            return Self::Expired;
        }
        match not_after_unix_seconds.saturating_sub(now_unix_seconds) {
            remaining if remaining <= SECONDS_PER_DAY => Self::Warning1Day,
            remaining if remaining <= 7 * SECONDS_PER_DAY => Self::Warning7Days,
            remaining if remaining <= 14 * SECONDS_PER_DAY => Self::Warning14Days,
            remaining if remaining <= 30 * SECONDS_PER_DAY => Self::Warning30Days,
            _ => Self::Valid,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Warning30Days => "warning_30_days",
            Self::Warning14Days => "warning_14_days",
            Self::Warning7Days => "warning_7_days",
            Self::Warning1Day => "warning_1_day",
            Self::Expired => "expired",
        }
    }

    const fn warning_threshold_days(self) -> Option<u8> {
        match self {
            Self::Warning30Days => Some(30),
            Self::Warning14Days => Some(14),
            Self::Warning7Days => Some(7),
            Self::Warning1Day => Some(1),
            Self::Valid | Self::Expired => None,
        }
    }
}

impl CertificateProof {
    fn expiry_state_at(&self, now_unix_seconds: u64) -> CertificateExpiryState {
        CertificateExpiryState::at(self.not_after_unix_seconds, now_unix_seconds)
    }
}

struct ProbeMatch {
    backend: Backend,
    certificate: CertificateProof,
}

#[derive(Clone)]
struct ActiveRoute {
    backend: Backend,
    certificate: CertificateProof,
    last_expiry_warning: Option<CertificateExpiryState>,
    declaration_generation: Option<u64>,
    last_tls_check: Instant,
    tcp_failures: u8,
}

impl ActiveRoute {
    fn certificate_is_valid_at(&self, now_unix_seconds: u64) -> bool {
        self.certificate.expiry_state_at(now_unix_seconds) != CertificateExpiryState::Expired
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteFailure {
    MissingRegistration,
    RegistryInvalid,
    VerificationFailed,
    CertificateExpired,
    CapacityUnavailable,
}

impl RouteFailure {
    fn label(self) -> &'static str {
        match self {
            Self::MissingRegistration => "missing_registration",
            Self::RegistryInvalid => "registry_invalid",
            Self::VerificationFailed => "verification_failed",
            Self::CertificateExpired => "certificate_expired",
            Self::CapacityUnavailable => "capacity_unavailable",
        }
    }
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |duration| duration.as_secs())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigReloadError {
    Invalid,
}

impl ConfigReloadError {
    fn label(self) -> &'static str {
        match self {
            Self::Invalid => "config_invalid",
        }
    }
}

#[derive(Default)]
struct ConfigReloadStatus {
    last_error: Option<ConfigReloadError>,
    accepted_reloads: u64,
    rejected_reloads: u64,
    last_rejected_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigReloadOutcome {
    NotPublic,
    Unchanged(u64),
    Accepted(u64),
    Rejected(u64),
    Superseded(u64),
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
struct AggregateEventWindow {
    last_emitted: Option<Instant>,
    pending: u64,
}

struct AggregateEvents<const N: usize> {
    windows: [AggregateEventWindow; N],
}

impl<const N: usize> AggregateEvents<N> {
    fn new() -> Self {
        Self {
            windows: [AggregateEventWindow::default(); N],
        }
    }

    fn record(&mut self, index: usize, now: Instant, interval: Duration) -> Option<u64> {
        let window = &mut self.windows[index];
        window.pending = window.pending.saturating_add(1);
        let should_emit = match window.last_emitted {
            Some(last_emitted) => now.saturating_duration_since(last_emitted) >= interval,
            None => true,
        };
        if !should_emit {
            return None;
        }
        window.last_emitted = Some(now);
        window.last_emitted = Some(now);
        Some(std::mem::take(&mut window.pending))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryOutcome {
    HandoffSuccess,
    HandoffFallback,
    HandoffPostDeliveryFailure,
    HandoffCapacityUnavailable,
    RelayStarted,
    RelayCompleted,
    RelayFailed,
}

impl DeliveryOutcome {
    const COUNT: usize = 7;
    #[cfg(test)]
    const ALL: [Self; Self::COUNT] = [
        Self::HandoffSuccess,
        Self::HandoffFallback,
        Self::HandoffPostDeliveryFailure,
        Self::HandoffCapacityUnavailable,
        Self::RelayStarted,
        Self::RelayCompleted,
        Self::RelayFailed,
    ];

    const fn index(self) -> usize {
        match self {
            Self::HandoffSuccess => 0,
            Self::HandoffFallback => 1,
            Self::HandoffPostDeliveryFailure => 2,
            Self::HandoffCapacityUnavailable => 3,
            Self::RelayStarted => 4,
            Self::RelayCompleted => 5,
            Self::RelayFailed => 6,
        }
    }

    const fn event(self) -> &'static str {
        match self {
            Self::HandoffSuccess
            | Self::HandoffFallback
            | Self::HandoffPostDeliveryFailure
            | Self::HandoffCapacityUnavailable => "handoff",
            Self::RelayStarted | Self::RelayCompleted | Self::RelayFailed => "relay",
        }
    }

    const fn result(self) -> &'static str {
        match self {
            Self::HandoffSuccess => "success",
            Self::HandoffFallback => "fallback",
            Self::HandoffPostDeliveryFailure => "post_delivery_failure",
            Self::HandoffCapacityUnavailable => "capacity_unavailable",
            Self::RelayStarted => "started",
            Self::RelayCompleted => "completed",
            Self::RelayFailed => "failed",
        }
    }
}

struct DeliveryEvent {
    outcome: DeliveryOutcome,
    count: u64,
}

impl std::fmt::Display for DeliveryEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "event={} result={} count={} suppressed={}",
            self.outcome.event(),
            self.outcome.result(),
            self.count,
            self.count.saturating_sub(1)
        )
    }
}

struct SourceDiagnosticEvent {
    source: IpAddr,
    hostname: String,
}

impl std::fmt::Display for SourceDiagnosticEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "event=source_diagnostic source={} hostname={}",
            self.source, self.hostname
        )
    }
}

struct ProxyState {
    config: PathBuf,
    production_paths: Option<ProductionPaths>,
    hosting_profile: RwLock<HostingProfile>,
    handoff_runtime: Option<PathBuf>,
    limits: ValidatedIngressLimits,
    admission: AdmissionController,
    listeners: RwLock<Vec<SocketAddr>>,
    routes: RwLock<HashMap<String, ActiveRoute>>,
    conflicts: RwLock<BTreeMap<String, Vec<Backend>>>,
    conflict_capacity_drops: AtomicU64,
    route_capacity_rejections: AtomicU64,
    route_failures: RwLock<BTreeMap<String, RouteFailure>>,
    undeclared_registrations: AtomicUsize,
    registry_valid: AtomicBool,
    rejected_registry_snapshots: AtomicU64,
    config_reload_status: Mutex<ConfigReloadStatus>,
    flights: Mutex<HashMap<String, Arc<DiscoveryFlight>>>,
    negative: Mutex<HashMap<String, Instant>>,
    workloads: Mutex<Vec<Backend>>,
    waiting_clients: AtomicUsize,
    queued_route_selections: Arc<AtomicUsize>,
    queued_connections: Arc<AtomicUsize>,
    probes: Arc<ProbeLimiter>,
    probe_connector_override: Option<TlsConnector>,
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
    rejected_routing_queue: AtomicU64,
    rejected_routing_timeout: AtomicU64,
    // Retained at zero for the versioned status and metric schemas after removing the delivery pool.
    rejected_worker_queue: AtomicU64,
    overload_events: Mutex<AggregateEvents<{ AdmissionRejection::COUNT }>>,
    delivery_events: Mutex<AggregateEvents<{ DeliveryOutcome::COUNT }>>,
    source_diagnostic_candidates: AtomicU64,
    source_diagnostic_last_emitted: Mutex<Option<Instant>>,
    successful_discoveries: AtomicU64,
    handoff_attempts: AtomicU64,
    successful_handoffs: AtomicU64,
    handoff_fallbacks: AtomicU64,
    handoff_capacity_skips: AtomicU64,
    delivered_handoff_failures: AtomicU64,
    completed_relays: AtomicU64,
    failed_relays: AtomicU64,
    relay_idle_timeouts: AtomicU64,
    relay_backend_connect_failures: AtomicU64,
    relay_client_to_workload_bytes: AtomicU64,
    relay_workload_to_client_bytes: AtomicU64,
    relay_duration_nanoseconds: AtomicU64,
}

impl ProxyState {
    fn with_limits(
        config: PathBuf,
        production_paths: Option<ProductionPaths>,
        hosting_profile: HostingProfile,
        handoff_runtime: Option<PathBuf>,
        limits: ValidatedIngressLimits,
        probe_connector_override: Option<TlsConnector>,
    ) -> Self {
        let admission = AdmissionController::new(&limits);
        Self {
            config,
            production_paths,
            hosting_profile: RwLock::new(hosting_profile),
            handoff_runtime,
            limits,
            admission,
            listeners: RwLock::new(Vec::new()),
            routes: RwLock::new(HashMap::new()),
            conflicts: RwLock::new(BTreeMap::new()),
            conflict_capacity_drops: AtomicU64::new(0),
            route_capacity_rejections: AtomicU64::new(0),
            route_failures: RwLock::new(BTreeMap::new()),
            undeclared_registrations: AtomicUsize::new(0),
            registry_valid: AtomicBool::new(true),
            rejected_registry_snapshots: AtomicU64::new(0),
            config_reload_status: Mutex::new(ConfigReloadStatus::default()),
            flights: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
            workloads: Mutex::new(Vec::new()),
            waiting_clients: AtomicUsize::new(0),
            queued_route_selections: Arc::new(AtomicUsize::new(0)),
            queued_connections: Arc::new(AtomicUsize::new(0)),
            probes: Arc::new(ProbeLimiter::new()),
            probe_connector_override,
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
            rejected_routing_queue: AtomicU64::new(0),
            rejected_routing_timeout: AtomicU64::new(0),
            rejected_worker_queue: AtomicU64::new(0),
            overload_events: Mutex::new(AggregateEvents::new()),
            delivery_events: Mutex::new(AggregateEvents::new()),
            source_diagnostic_candidates: AtomicU64::new(0),
            source_diagnostic_last_emitted: Mutex::new(None),
            successful_discoveries: AtomicU64::new(0),
            handoff_attempts: AtomicU64::new(0),
            successful_handoffs: AtomicU64::new(0),
            handoff_fallbacks: AtomicU64::new(0),
            handoff_capacity_skips: AtomicU64::new(0),
            delivered_handoff_failures: AtomicU64::new(0),
            completed_relays: AtomicU64::new(0),
            failed_relays: AtomicU64::new(0),
            relay_idle_timeouts: AtomicU64::new(0),
            relay_backend_connect_failures: AtomicU64::new(0),
            relay_client_to_workload_bytes: AtomicU64::new(0),
            relay_workload_to_client_bytes: AtomicU64::new(0),
            relay_duration_nanoseconds: AtomicU64::new(0),
        }
    }

    fn hosting_profile(&self) -> HostingProfile {
        self.hosting_profile
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn public_snapshot(&self) -> Option<Arc<PublicIngressSnapshot>> {
        self.hosting_profile().public_snapshot()
    }

    fn relay_idle_timeout(&self, hostname: &str) -> Option<Duration> {
        match self.public_snapshot() {
            Some(snapshot) => snapshot
                .routes
                .get(hostname)
                .map_or(Some(DEFAULT_RELAY_IDLE_TIMEOUT), |route| {
                    route.relay_idle_timeout
                }),
            None => None,
        }
    }

    fn route_cache(&self) -> Option<(&Path, route_cache::Storage)> {
        let profile = self
            .hosting_profile
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.route_cache_for_profile(&profile)
    }

    fn route_cache_for_profile(
        &self,
        profile: &HostingProfile,
    ) -> Option<(&Path, route_cache::Storage)> {
        match (&self.production_paths, profile) {
            (Some(paths), HostingProfile::Public(_)) => {
                Some((&paths.route_cache, route_cache::Storage::SeparateState))
            }
            (None, HostingProfile::Public(_)) => None,
            (_, HostingProfile::Development) => {
                Some((&self.config, route_cache::Storage::CombinedRegistry))
            }
        }
    }

    #[cfg(unix)]
    fn control_socket_path(&self) -> PathBuf {
        self.production_paths
            .as_ref()
            .map(ProductionPaths::control_socket)
            .unwrap_or_else(development_control_socket_path)
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
        Self::with_limits(config, None, hosting_profile, None, limits, None)
    }

    #[cfg(test)]
    fn new_with_profile_and_connector(
        config: PathBuf,
        hosting_profile: HostingProfile,
        tls_connector: TlsConnector,
    ) -> Self {
        let limits = IngressLimits::default()
            .validate(
                SystemCapacity {
                    file_descriptors: None,
                    tasks: None,
                },
                2,
            )
            .unwrap();
        Self::with_limits(
            config,
            None,
            hosting_profile,
            None,
            limits,
            Some(tls_connector),
        )
    }

    #[cfg(test)]
    fn new_with_profile_connector_and_runtime(
        config: PathBuf,
        hosting_profile: HostingProfile,
        tls_connector: TlsConnector,
        handoff_runtime: PathBuf,
    ) -> Self {
        let limits = IngressLimits::default()
            .validate(
                SystemCapacity {
                    file_descriptors: None,
                    tasks: None,
                },
                2,
            )
            .unwrap();
        Self::with_limits(
            config,
            None,
            hosting_profile,
            Some(handoff_runtime),
            limits,
            Some(tls_connector),
        )
    }

    #[cfg(test)]
    fn new_with_production_paths(
        hosting_profile: HostingProfile,
        production_paths: ProductionPaths,
    ) -> Self {
        let limits = IngressLimits::default()
            .validate(
                SystemCapacity {
                    file_descriptors: None,
                    tasks: None,
                },
                2,
            )
            .unwrap();
        let config = production_paths.port_registry.clone();
        let handoff_runtime = production_paths.runtime_root.clone();
        Self::with_limits(
            config,
            Some(production_paths),
            hosting_profile,
            Some(handoff_runtime),
            limits,
            None,
        )
    }

    fn discover_once(
        &self,
        hostname: &str,
        discover: impl FnOnce() -> Result<Backend, String>,
    ) -> Result<Backend, String> {
        self.discover_once_until(hostname, Instant::now() + DISCOVERY_TIMEOUT, |_| discover())
    }

    fn discover_once_until(
        &self,
        hostname: &str,
        deadline: Instant,
        discover: impl FnOnce(Instant) -> Result<Backend, String>,
    ) -> Result<Backend, String> {
        ensure_before_route_deadline(deadline)?;
        let _waiting = WaitingClient::acquire(&self.waiting_clients)?;
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

        ensure_before_route_deadline(deadline)?;
        let result = discover(deadline);
        flight.complete(result.clone());
        if let Ok(mut flights) = self.flights.lock() {
            flights.remove(hostname);
        }
        ensure_before_route_deadline(deadline)?;
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
            AdmissionRejection::RoutingQueue => &self.rejected_routing_queue,
            AdmissionRejection::RoutingTimeout => &self.rejected_routing_timeout,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.overload_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(rejection.index(), now, OVERLOAD_EVENT_INTERVAL)
            .map(|rejected| OverloadEvent {
                reason: rejection,
                rejected,
            })
    }

    fn record_delivery_outcome(&self, outcome: DeliveryOutcome) {
        if let Some(event) = self.record_delivery_outcome_at(outcome, Instant::now()) {
            eprintln!("{event}");
        }
    }

    fn record_delivery_outcome_at(
        &self,
        outcome: DeliveryOutcome,
        now: Instant,
    ) -> Option<DeliveryEvent> {
        self.delivery_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(outcome.index(), now, DELIVERY_EVENT_INTERVAL)
            .map(|count| DeliveryEvent { outcome, count })
    }

    fn record_relay_report(&self, report: &relay::RelayReport) {
        saturating_atomic_add(
            &self.relay_client_to_workload_bytes,
            report.client_to_workload_bytes,
        );
        saturating_atomic_add(
            &self.relay_workload_to_client_bytes,
            report.workload_to_client_bytes,
        );
        let elapsed = report
            .elapsed
            .as_nanos()
            .min(u128::from(u64::MAX))
            .try_into()
            .unwrap_or(u64::MAX);
        saturating_atomic_add(&self.relay_duration_nanoseconds, elapsed);
    }

    fn record_source_diagnostic(&self, source: IpAddr, hostname: &str) {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return;
        };
        if let Some(event) =
            self.record_source_diagnostic_at(source, hostname, now.as_secs(), Instant::now())
        {
            eprintln!("{event}");
        }
    }

    fn record_source_diagnostic_at(
        &self,
        source: IpAddr,
        hostname: &str,
        unix_seconds: u64,
        now: Instant,
    ) -> Option<SourceDiagnosticEvent> {
        let diagnostics = self.public_snapshot()?.source_diagnostics?;
        if !diagnostics.active_at(unix_seconds) {
            return None;
        }
        let candidate = self
            .source_diagnostic_candidates
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if !candidate.is_multiple_of(diagnostics.sample_every) {
            return None;
        }
        let mut last_emitted = self
            .source_diagnostic_last_emitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last_emitted.is_some_and(|previous| {
            now.saturating_duration_since(previous) < SOURCE_DIAGNOSTIC_EVENT_INTERVAL
        }) {
            return None;
        }
        *last_emitted = Some(now);
        Some(SourceDiagnosticEvent {
            source,
            hostname: hostname.to_string(),
        })
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

struct QueuedRouteSelection {
    count: Arc<AtomicUsize>,
}

impl QueuedRouteSelection {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self { count }
    }
}

impl Drop for QueuedRouteSelection {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

struct RouteSelectionJob {
    hostname: String,
    deadline: Instant,
    result: oneshot::Sender<Result<Backend, String>>,
    queued: QueuedRouteSelection,
}

#[derive(Clone)]
struct TokioIngress {
    state: Arc<ProxyState>,
    shutdown: IngressShutdown,
    route_sender: mpsc::SyncSender<RouteSelectionJob>,
}

struct ListenerDrainReport {
    forced_connections: usize,
    failure: Option<String>,
}

struct IngressDrainReport {
    forced_connections: usize,
    failure: Option<String>,
}

struct HandoffJob {
    client: TcpStream,
    accepted_at: Instant,
    admission: PreRoutingAdmission,
    hostname: String,
    peeked_length: usize,
    backend: Backend,
    cached: bool,
    relay_idle_timeout: Option<Duration>,
}

struct RelayJob {
    client: TcpStream,
    admission: PreRoutingAdmission,
    hostname: String,
    backend: Backend,
    cached: bool,
    idle_timeout: Option<Duration>,
}

struct EstablishedRelay {
    client: TokioTcpStream,
    upstream: TokioTcpStream,
    _admission: RelayAdmission,
    idle_timeout: Option<Duration>,
}

fn same_route_target(left: &RouteDeclaration, right: &RouteDeclaration) -> bool {
    left.workload == right.workload && left.role == right.role
}

fn record_config_reload_failure(state: &ProxyState, rejected_generation: u64) {
    let mut status = state
        .config_reload_status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    status.last_rejected_generation = Some(rejected_generation);
    if status.last_error == Some(ConfigReloadError::Invalid) {
        return;
    }
    status.last_error = Some(ConfigReloadError::Invalid);
    status.rejected_reloads = status.rejected_reloads.saturating_add(1);
    eprintln!("event=ingress_config_reload result=rejected reason=config_invalid");
}

fn clear_config_reload_failure(state: &ProxyState) {
    state
        .config_reload_status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .last_error = None;
}

fn reload_public_profile(state: &ProxyState) -> ConfigReloadOutcome {
    let current = state.hosting_profile();
    let Some(current_snapshot) = current.public_snapshot() else {
        return ConfigReloadOutcome::NotPublic;
    };
    let replacement = match current.reload() {
        Ok(Some(replacement)) => replacement,
        Ok(None) => {
            clear_config_reload_failure(state);
            return ConfigReloadOutcome::Unchanged(current_snapshot.generation);
        }
        Err(_) => {
            record_config_reload_failure(state, current_snapshot.generation.saturating_add(1));
            return ConfigReloadOutcome::Rejected(current_snapshot.generation.saturating_add(1));
        }
    };
    let replacement_snapshot = replacement
        .public_snapshot()
        .expect("a public config reload returns a public snapshot");

    let mut profile = state
        .hosting_profile
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(installed_snapshot) = profile.public_snapshot() else {
        return ConfigReloadOutcome::NotPublic;
    };
    if installed_snapshot.generation != current_snapshot.generation {
        return ConfigReloadOutcome::Superseded(installed_snapshot.generation);
    }
    let mut routes = state
        .routes
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    routes.retain(|hostname, active| {
        let Some(previous) = current_snapshot.routes.get(hostname) else {
            return false;
        };
        let Some(next) = replacement_snapshot.routes.get(hostname) else {
            return false;
        };
        if active.declaration_generation == Some(current_snapshot.generation)
            && same_route_target(previous, next)
        {
            active.declaration_generation = Some(replacement_snapshot.generation);
            true
        } else {
            false
        }
    });
    *profile = replacement;
    drop(routes);
    drop(profile);

    state
        .route_failures
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|hostname, _| {
            current_snapshot
                .routes
                .get(hostname)
                .zip(replacement_snapshot.routes.get(hostname))
                .is_some_and(|(previous, next)| same_route_target(previous, next))
        });
    state
        .conflicts
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    state
        .negative
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    if let Some((route_cache_path, route_cache_storage)) = state.route_cache() {
        let targets = replacement_snapshot
            .routes
            .iter()
            .map(|(hostname, declaration)| {
                (
                    hostname.clone(),
                    (declaration.workload.clone(), declaration.role.clone()),
                )
            })
            .collect();
        if route_cache::retain_targets(route_cache_path, route_cache_storage, &targets).is_err() {
            eprintln!("event=route_state_update result=failed");
        }
    }
    {
        let mut status = state
            .config_reload_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.last_error = None;
        status.accepted_reloads = status.accepted_reloads.saturating_add(1);
    }
    eprintln!(
        "event=ingress_config_reload result=accepted generation={} declared_routes={}",
        replacement_snapshot.generation,
        replacement_snapshot.routes.len()
    );
    ConfigReloadOutcome::Accepted(replacement_snapshot.generation)
}

fn record_registry_snapshot_failure(state: &ProxyState) {
    if state.registry_valid.swap(false, Ordering::AcqRel) {
        let _ = state.rejected_registry_snapshots.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |count| Some(count.saturating_add(1)),
        );
        eprintln!("event=port_registry_reload result=rejected reason=registry_invalid");
    }
}

fn record_registry_snapshot_success(state: &ProxyState) {
    if !state.registry_valid.swap(true, Ordering::AcqRel) {
        eprintln!("event=port_registry_reload result=recovered");
    }
}

fn set_route_failure(state: &ProxyState, hostname: &str, failure: RouteFailure) {
    let mut failures = state
        .route_failures
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if failures.contains_key(hostname) || failures.len() < MAX_ROUTE_DECLARATIONS {
        failures.insert(hostname.to_string(), failure);
    }
}

fn clear_route_failure(state: &ProxyState, hostname: &str) {
    state
        .route_failures
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(hostname);
}

pub fn run(config: DaemonConfig) -> Result<(), String> {
    PROCESS_START.get_or_init(Instant::now);
    let DaemonConfig {
        listen_addresses,
        listeners_explicit,
        ingress_config,
        run_as,
        limits,
        task_budget,
    } = config;
    let privilege_drop = privilege::prepare(run_as.as_deref())?;
    if privilege_drop.is_some() && !listeners_explicit {
        return Err("--run-as requires at least one explicit --listen address".to_string());
    }
    let loopback_only = listen_addresses.iter().all(|address| {
        address
            .parse::<SocketAddr>()
            .is_ok_and(|address| address.ip().is_loopback())
    });

    let (hosting_profile, production_paths, acquired_listeners, limits) =
        if let Some(privilege_drop) = privilege_drop {
            let limits = limits.validate_for_startup(task_budget, listen_addresses.len(), true)?;
            let acquired_listeners = activated_listener::acquire_direct(&listen_addresses)?;
            privilege_drop.apply()?;
            let hosting_profile = HostingProfile::load_for_daemon(ingress_config, loopback_only)?;
            let bound_addresses = acquired_listeners
                .iter()
                .map(|acquired| {
                    acquired
                        .listener
                        .local_addr()
                        .map_err(|error| format!("cannot read bound listener address: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            hosting_profile.validate_bound_listeners(&bound_addresses, true)?;
            let production_paths = prepare_production_paths(&hosting_profile)?;
            (
                hosting_profile,
                production_paths,
                acquired_listeners,
                limits,
            )
        } else {
            let hosting_profile = HostingProfile::load_for_daemon(ingress_config, loopback_only)?;
            hosting_profile.validate_daemon_listeners(&listen_addresses, false)?;
            let metrics_enabled = hosting_profile
                .public_snapshot()
                .is_some_and(|snapshot| snapshot.metrics.is_some());
            let limits = limits.validate_for_startup(
                task_budget,
                listen_addresses.len(),
                metrics_enabled,
            )?;
            let production_paths = prepare_production_paths(&hosting_profile)?;
            let acquired_listeners = activated_listener::acquire(&listen_addresses)?;
            (
                hosting_profile,
                production_paths,
                acquired_listeners,
                limits,
            )
        };
    let shutdown_drain_timeout = if production_paths.is_some() {
        PUBLIC_SHUTDOWN_DRAIN_TIMEOUT
    } else {
        DEVELOPMENT_SHUTDOWN_DRAIN_TIMEOUT
    };
    let registry = production_paths
        .as_ref()
        .map(|paths| paths.port_registry.clone())
        .unwrap_or_else(config_path);
    let handoff_runtime = production_paths
        .as_ref()
        .map(|paths| paths.runtime_root.clone())
        .or_else(handoff::runtime_override);
    let state = Arc::new(ProxyState::with_limits(
        registry,
        production_paths,
        hosting_profile,
        handoff_runtime,
        limits,
        None,
    ));
    let shutdown = IngressShutdown::new(shutdown_drain_timeout);
    let mut listeners = Vec::with_capacity(acquired_listeners.len());

    for acquired in acquired_listeners {
        let address = acquired
            .listener
            .local_addr()
            .map_err(|error| format!("cannot read listener address: {error}"))?;
        match acquired.origin {
            ListenerOrigin::Direct => eprintln!("TLS proxy listening on {address}"),
            #[cfg(target_os = "linux")]
            ListenerOrigin::Systemd(name) => {
                eprintln!("Adopted systemd listener {name} on {address}")
            }
            #[cfg(target_os = "macos")]
            ListenerOrigin::Launchd(name) => {
                eprintln!("Adopted launchd listener {name} on {address}")
            }
        }
        listeners.push(acquired.listener);
    }
    *state
        .listeners
        .write()
        .map_err(|_| "listener state lock poisoned".to_string())? = listeners
        .iter()
        .filter_map(|listener| listener.local_addr().ok())
        .collect();

    let signal = shutdown.clone();
    ctrlc::set_handler(move || signal.request())
        .map_err(|error| format!("cannot install shutdown signal handler: {error}"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(TOKIO_RUNTIME_WORKERS)
        // PHXP is the only spawn_blocking caller; every possible worker is admission- and
        // task-budgeted by handoff_negotiations before work reaches Tokio.
        .max_blocking_threads(state.limits.handoff_workers())
        .thread_name("phx-port-tokio")
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("cannot start Tokio ingress runtime: {error}"))?;

    let route_state = Arc::clone(&state);
    let mut route_workers = BoundedWorkerPool::start(
        "phx-port-route",
        ROUTE_SELECTION_WORKERS,
        ROUTE_SELECTION_QUEUE_CAPACITY,
        move |job: RouteSelectionJob| handle_route_selection(job, &route_state),
    )?;

    #[cfg(unix)]
    let (control_path, control_thread) =
        match start_control_server(Arc::clone(&state), shutdown.clone()) {
            Ok(control) => control,
            Err(error) => {
                route_workers.close();
                let _ = route_workers.join();
                return Err(error);
            }
        };
    let metrics_thread = start_metrics_server(Arc::clone(&state), shutdown.clone());

    let reconciler_thread = {
        let state = Arc::clone(&state);
        let shutdown = shutdown.requested_flag();
        thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                thread::sleep(LIVENESS_INTERVAL);
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                reload_public_profile(&state);
                reconcile_workloads(&state);
                reconcile_routes(&state);
            }
        })
    };

    let ingress_report = runtime.block_on(serve_tokio_ingress(
        listeners,
        Arc::clone(&state),
        shutdown.clone(),
        route_workers.sender(),
    ));
    shutdown.request();
    let drain_deadline = shutdown.drain_deadline();
    let handoffs_pending = state.admission.snapshot().handoff.in_use > 0;
    let blocking_grace = if handoffs_pending {
        PHXP_SHUTDOWN_GRACE
    } else {
        Duration::ZERO
    };
    runtime.shutdown_timeout(
        drain_deadline
            .saturating_duration_since(Instant::now())
            .max(blocking_grace),
    );

    route_workers.close();
    let route_join_error = route_workers.join().err();
    let _ = reconciler_thread.join();

    let remaining = state.admission.snapshot().global.in_use;
    let drain_result = if ingress_report.failure.is_some() || route_join_error.is_some() {
        "failed"
    } else if ingress_report.forced_connections > 0 || remaining > 0 {
        "drain_timeout"
    } else {
        "complete"
    };
    let duration_ms = shutdown
        .drain_elapsed()
        .as_millis()
        .min(u128::from(u64::MAX));
    eprintln!(
        "event=ingress_shutdown result={drain_result} duration_ms={duration_ms} \
         forced_connections={} active_connections={remaining}",
        ingress_report.forced_connections
    );

    shutdown.finish();
    #[cfg(unix)]
    let _ = control_thread.join();
    if let Some(metrics_thread) = metrics_thread {
        let _ = metrics_thread.join();
    }

    #[cfg(unix)]
    if let Err(error) = std::fs::remove_file(&control_path)
        && error.kind() != io::ErrorKind::NotFound
    {
        eprintln!("Could not remove control socket: {error}");
    }
    if let Some(error) = route_join_error {
        return Err(error);
    }
    if let Some(error) = ingress_report.failure {
        return Err(error);
    }
    eprintln!("TLS proxy stopped");
    Ok(())
}

async fn serve_tokio_ingress(
    listeners: Vec<std::net::TcpListener>,
    state: Arc<ProxyState>,
    shutdown: IngressShutdown,
    route_sender: mpsc::SyncSender<RouteSelectionJob>,
) -> IngressDrainReport {
    let mut listener_tasks = JoinSet::new();
    let mut failure = None;
    let mut forced_connections = 0;
    for listener in listeners {
        let listener = match TokioTcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(error) => {
                failure = Some(format!("cannot adopt listener into Tokio: {error}"));
                shutdown.request();
                break;
            }
        };
        let ingress = TokioIngress {
            state: Arc::clone(&state),
            shutdown: shutdown.clone(),
            route_sender: route_sender.clone(),
        };
        listener_tasks.spawn(async move { accept_tokio_connections(listener, ingress).await });
    }
    drop(route_sender);

    while !listener_tasks.is_empty() {
        tokio::select! {
            biased;
            _ = shutdown.wait_requested() => break,
            Some(joined) = listener_tasks.join_next() => {
                match joined {
                    Ok(report) => {
                        forced_connections += report.forced_connections;
                        if failure.is_none() {
                            failure = report.failure;
                        }
                        if !shutdown.is_requested() {
                            failure =
                                Some("Tokio ingress listener stopped unexpectedly".to_string());
                            shutdown.request();
                        }
                    }
                    Err(error) => {
                        failure = Some(format!("Tokio ingress listener task failed: {error}"));
                        shutdown.request();
                    }
                }
            }
        }
    }

    shutdown.request();
    state
        .listeners
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    while let Some(joined) = listener_tasks.join_next().await {
        match joined {
            Ok(report) => {
                forced_connections += report.forced_connections;
                if failure.is_none() {
                    failure = report.failure;
                }
            }
            Err(error) if failure.is_none() => {
                failure = Some(format!("Tokio ingress listener task failed: {error}"));
            }
            _ => {}
        }
    }

    IngressDrainReport {
        forced_connections,
        failure,
    }
}

async fn accept_tokio_connections(
    listener: TokioTcpListener,
    ingress: TokioIngress,
) -> ListenerDrainReport {
    let TokioIngress {
        state,
        shutdown,
        route_sender,
    } = ingress;
    let mut connections = JoinSet::new();
    let mut failure = None;
    let mut accept_error_reported = false;

    loop {
        reap_ready_connection_tasks(&mut connections, &state, &mut failure);
        if failure.is_some() {
            shutdown.request();
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.wait_requested() => break,
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                record_connection_completion(joined, &state, &mut failure);
                if failure.is_some() {
                    shutdown.request();
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        accept_error_reported = false;
                        if shutdown.is_requested() {
                            break;
                        }
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
                        let ingress = TokioIngress {
                            state: Arc::clone(&state),
                            shutdown: shutdown.clone(),
                            route_sender: route_sender.clone(),
                        };
                        connections.spawn(async move {
                            route_tokio_connection(
                                stream,
                                peer.ip(),
                                accepted_at,
                                admission,
                                ingress,
                            )
                            .await
                        });
                    }
                    Err(error) => {
                        if !accept_error_reported {
                            eprintln!("TLS proxy accept failed: {error}");
                            accept_error_reported = true;
                        }
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
        }
    }

    drop(listener);
    let forced_connections = drain_connection_tasks(
        &mut connections,
        &state,
        &mut failure,
        shutdown.drain_deadline(),
    )
    .await;

    ListenerDrainReport {
        forced_connections,
        failure,
    }
}

async fn drain_connection_tasks(
    connections: &mut JoinSet<Result<(), String>>,
    state: &ProxyState,
    failure: &mut Option<String>,
    drain_deadline: Instant,
) -> usize {
    let drain_deadline = tokio::time::Instant::from_std(drain_deadline);
    while !connections.is_empty() {
        tokio::select! {
            joined = connections.join_next() => {
                if let Some(joined) = joined {
                    record_connection_completion(joined, state, failure);
                }
            }
            _ = tokio::time::sleep_until(drain_deadline) => break,
        }
    }

    connections.abort_all();
    let mut forced_connections = 0;
    while let Some(joined) = connections.join_next().await {
        if matches!(&joined, Err(error) if error.is_cancelled()) {
            forced_connections += 1;
        }
        record_connection_completion(joined, state, failure);
    }
    forced_connections
}

fn reap_ready_connection_tasks(
    connections: &mut JoinSet<Result<(), String>>,
    state: &ProxyState,
    failure: &mut Option<String>,
) -> usize {
    let mut reaped = 0;
    while let Some(joined) = connections.try_join_next() {
        reaped += 1;
        record_connection_completion(joined, state, failure);
    }
    reaped
}

fn record_connection_completion(
    joined: Result<Result<(), String>, tokio::task::JoinError>,
    state: &ProxyState,
    failure: &mut Option<String>,
) {
    match joined {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            state.rejected_connections.fetch_add(1, Ordering::Relaxed);
        }
        Err(error) if error.is_cancelled() => {}
        Err(error) if failure.is_none() => {
            *failure = Some(format!("Tokio connection task failed: {error}"));
        }
        Err(_) => {}
    }
}

async fn route_tokio_connection(
    client: TokioTcpStream,
    source: IpAddr,
    accepted_at: Instant,
    admission: PreRoutingAdmission,
    ingress: TokioIngress,
) -> Result<(), String> {
    let handoff = tokio::select! {
        biased;
        _ = ingress.shutdown.wait_requested() => return Ok(()),
        result = prepare_tokio_handoff(client, source, accepted_at, admission, &ingress) => result?,
    };
    if ingress.shutdown.is_requested() {
        return Ok(());
    }

    match prepare_handoff(handoff, Arc::clone(&ingress.state)).await? {
        None => Ok(()),
        Some(_) if ingress.shutdown.is_requested() => Ok(()),
        Some(job) => relay_tokio_connection(job, &ingress).await,
    }
}

async fn prepare_tokio_handoff(
    client: TokioTcpStream,
    source: IpAddr,
    accepted_at: Instant,
    admission: PreRoutingAdmission,
    ingress: &TokioIngress,
) -> Result<HandoffJob, String> {
    let state = &ingress.state;
    let client_hello_deadline = accepted_at
        .checked_add(state.limits.client_hello_timeout())
        .ok_or_else(|| "ClientHello deadline overflowed".to_string())?;
    let (hostname, peeked_length) = tls_client_hello::peek_sni_async(
        &client,
        tokio::time::Instant::from_std(client_hello_deadline),
    )
    .await
    .map_err(|error| error.to_string())?;
    state.record_source_diagnostic(source, &hostname);

    let (backend, cached) = select_tokio_route(&hostname, ingress).await?;
    let relay_idle_timeout = state.relay_idle_timeout(&hostname);
    let client = client
        .into_std()
        .map_err(|error| format!("cannot release accepted socket from Tokio: {error}"))?;
    Ok(HandoffJob {
        client,
        accepted_at,
        admission,
        hostname,
        peeked_length,
        backend,
        cached,
        relay_idle_timeout,
    })
}

async fn select_tokio_route(
    hostname: &str,
    ingress: &TokioIngress,
) -> Result<(Backend, bool), String> {
    if let Some(backend) = current_active_backend(&ingress.state, hostname)? {
        return Ok((backend, true));
    }

    let deadline = Instant::now()
        .checked_add(DISCOVERY_TIMEOUT)
        .ok_or_else(|| "route-selection deadline overflowed".to_string())?;
    let (result, receiver) = oneshot::channel();
    let job = RouteSelectionJob {
        hostname: hostname.to_string(),
        deadline,
        result,
        queued: QueuedRouteSelection::new(Arc::clone(&ingress.state.queued_route_selections)),
    };
    match ingress.route_sender.try_send(job) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            ingress
                .state
                .record_admission_rejection(AdmissionRejection::RoutingQueue);
            return Err("route-selection queue capacity exhausted".to_string());
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            if !ingress.shutdown.is_requested() {
                eprintln!("TLS proxy route-selection worker pool stopped");
            }
            ingress.shutdown.request();
            return Err("route-selection worker pool stopped".to_string());
        }
    }

    let received =
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receiver).await;
    if Instant::now() >= deadline {
        ingress
            .state
            .record_admission_rejection(AdmissionRejection::RoutingTimeout);
        return Err("route selection timed out".to_string());
    }
    match received {
        Ok(Ok(result)) => result.map(|backend| (backend, false)),
        Ok(Err(_)) => Err("route-selection worker dropped its result".to_string()),
        Err(_) => {
            ingress
                .state
                .record_admission_rejection(AdmissionRejection::RoutingTimeout);
            Err("route selection timed out".to_string())
        }
    }
}

fn current_active_backend(state: &ProxyState, hostname: &str) -> Result<Option<Backend>, String> {
    loop {
        let active = state
            .routes
            .read()
            .map_err(|_| "route table lock poisoned".to_string())?
            .get(hostname)
            .cloned();
        let Some(active) = active else {
            return Ok(None);
        };
        let now_unix_seconds = current_unix_seconds();
        if active.certificate_is_valid_at(now_unix_seconds) {
            return Ok(Some(active.backend));
        }
        if deactivate_expired_route(state, hostname, now_unix_seconds) {
            return Ok(None);
        }
    }
}

fn handle_route_selection(job: RouteSelectionJob, state: &ProxyState) {
    let RouteSelectionJob {
        hostname,
        deadline,
        result,
        queued,
    } = job;
    drop(queued);
    if result.is_closed() || Instant::now() >= deadline {
        return;
    }
    let resolved = resolve_backend_until(&hostname, state, deadline);
    if result.is_closed() || Instant::now() >= deadline {
        return;
    }
    let _ = result.send(resolved);
}

fn start_metrics_server(
    state: Arc<ProxyState>,
    shutdown: IngressShutdown,
) -> Option<thread::JoinHandle<()>> {
    let metrics = state.public_snapshot()?.metrics?;
    let render_state = Arc::clone(&state);
    let exiting = Arc::clone(&shutdown.exiting);
    match observability::start_metrics_server(metrics.listen, exiting, move || {
        render_prometheus_metrics(&render_state, &shutdown)
    }) {
        Ok(metrics_thread) => {
            eprintln!(
                "event=metrics_listener result=started address={}",
                metrics.listen
            );
            Some(metrics_thread)
        }
        Err(error) => {
            eprintln!(
                "event=metrics_listener result=unavailable reason={}",
                error.reason()
            );
            None
        }
    }
}

fn prepare_production_paths(
    hosting_profile: &HostingProfile,
) -> Result<Option<ProductionPaths>, String> {
    let Some(snapshot) = hosting_profile.public_snapshot() else {
        return Ok(None);
    };
    let paths = ProductionPaths::from_environment()?;
    paths.validate_intent_separation(&snapshot.ingress_config)?;
    paths.prepare_for_startup()?;
    Ok(Some(paths))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthCheck {
    Live,
    Ready,
}

impl HealthCheck {
    fn command(self) -> &'static str {
        match self {
            Self::Live => "CHECK LIVE",
            Self::Ready => "CHECK READY",
        }
    }

    fn satisfied_by(self, health: &ControlHealth) -> bool {
        match self {
            Self::Live => health.live,
            Self::Ready => health.ready,
        }
    }
}

#[derive(Deserialize)]
struct ControlHealth {
    schema_version: u32,
    live: bool,
    ready: bool,
}

pub fn query_health(check: HealthCheck) -> Result<(String, bool), String> {
    let response = query_control(check.command())?;
    let health = serde_json::from_str::<ControlHealth>(&response)
        .map_err(|error| format!("daemon returned invalid health JSON: {error}"))?;
    if health.schema_version != CONTROL_SCHEMA_VERSION {
        return Err(format!(
            "daemon returned unsupported health schema version {}",
            health.schema_version
        ));
    }
    let satisfied = check.satisfied_by(&health);
    Ok((response, satisfied))
}

pub fn query_control(command: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        let mut stream = UnixStream::connect(client_control_socket_path()?)
            .map_err(|error| format!("TLS proxy daemon is not reachable: {error}"))?;
        stream
            .set_read_timeout(Some(CONTROL_IO_TIMEOUT))
            .map_err(|error| format!("cannot configure control connection: {error}"))?;
        stream
            .set_write_timeout(Some(CONTROL_IO_TIMEOUT))
            .map_err(|error| format!("cannot configure control connection: {error}"))?;
        stream
            .write_all(format!("{command}\n").as_bytes())
            .map_err(|error| format!("cannot send daemon command: {error}"))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| format!("cannot finish daemon command: {error}"))?;
        let mut response = Vec::new();
        (&mut stream)
            .take(CONTROL_RESPONSE_LIMIT + 1)
            .read_to_end(&mut response)
            .map_err(|error| format!("cannot read daemon response: {error}"))?;
        if response.len() as u64 > CONTROL_RESPONSE_LIMIT {
            return Err(format!(
                "daemon response exceeds the {CONTROL_RESPONSE_LIMIT} byte limit"
            ));
        }
        let response = String::from_utf8(response)
            .map_err(|_| "daemon response is not valid UTF-8".to_string())?;
        if let Some(error) = response.strip_prefix("ERROR ") {
            return Err(format!(
                "TLS proxy control request failed: {}",
                error.trim()
            ));
        }
        Ok(response)
    }

    #[cfg(not(unix))]
    Err("live daemon status is not supported on this platform".to_string())
}

#[cfg(unix)]
fn client_control_socket_path() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("PHX_PORT_INGRESS_CONFIG") {
        if value.is_empty() {
            return Err("PHX_PORT_INGRESS_CONFIG must not be empty".to_string());
        }
        return ProductionPaths::from_environment().map(|paths| paths.control_socket());
    }
    Ok(development_control_socket_path())
}

#[cfg(unix)]
fn development_control_socket_path() -> PathBuf {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControlPeer {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlAccess {
    ReadOnly,
    Mutation,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlAuthorization {
    Development { owner_uid: u32 },
    Public { service_uid: u32, admin_gid: u32 },
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControlEndpointPolicy {
    authorization: ControlAuthorization,
    socket_mode: u32,
    socket_gid: Option<u32>,
}

#[cfg(unix)]
impl ControlEndpointPolicy {
    fn development() -> Self {
        Self {
            authorization: ControlAuthorization::Development {
                owner_uid: nix::unistd::geteuid().as_raw(),
            },
            socket_mode: 0o600,
            socket_gid: None,
        }
    }

    fn public(admin_gid: u32) -> Self {
        Self {
            authorization: ControlAuthorization::Public {
                service_uid: nix::unistd::geteuid().as_raw(),
                admin_gid,
            },
            socket_mode: 0o660,
            socket_gid: Some(admin_gid),
        }
    }

    fn authorizes(self, peer: ControlPeer, access: ControlAccess) -> bool {
        match self.authorization {
            ControlAuthorization::Development { owner_uid } => {
                peer.uid == 0 || peer.uid == owner_uid
            }
            ControlAuthorization::Public {
                service_uid,
                admin_gid,
            } => match access {
                ControlAccess::Mutation => peer.uid == 0,
                ControlAccess::ReadOnly => {
                    peer.uid == 0
                        || peer.uid == service_uid
                        || peer_belongs_to_group(peer, admin_gid)
                }
            },
        }
    }
}

#[cfg(unix)]
fn control_command_access(request: &str) -> Option<ControlAccess> {
    match request {
        "STATUS" | "STATUS JSON" | "ROUTES" | "CHECK LIVE" | "CHECK READY" => {
            Some(ControlAccess::ReadOnly)
        }
        "RELOAD" | "STOP" => Some(ControlAccess::Mutation),
        _ => None,
    }
}

#[cfg(unix)]
fn peer_belongs_to_group(peer: ControlPeer, admin_gid: u32) -> bool {
    if peer.gid == admin_gid {
        return true;
    }
    let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(peer.uid)) else {
        return false;
    };
    if user.gid.as_raw() == admin_gid {
        return true;
    }
    let Ok(Some(group)) = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(admin_gid))
    else {
        return false;
    };
    group.mem.iter().any(|member| member == &user.name)
}

#[cfg(target_os = "linux")]
fn control_peer(stream: &UnixStream) -> Result<ControlPeer, String> {
    use nix::sys::socket::{getsockopt, sockopt};

    let credentials = getsockopt(stream, sockopt::PeerCredentials)
        .map_err(|error| format!("cannot authenticate control peer: {error}"))?;
    Ok(ControlPeer {
        uid: credentials.uid(),
        gid: credentials.gid(),
    })
}

#[cfg(target_os = "macos")]
fn control_peer(stream: &UnixStream) -> Result<ControlPeer, String> {
    let (uid, gid) = nix::unistd::getpeereid(stream)
        .map_err(|error| format!("cannot authenticate control peer: {error}"))?;
    Ok(ControlPeer {
        uid: uid.as_raw(),
        gid: gid.as_raw(),
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn control_peer(_stream: &UnixStream) -> Result<ControlPeer, String> {
    Err("control peer authentication is supported only on Linux and macOS".to_string())
}

#[cfg(unix)]
fn validate_control_socket(
    path: &Path,
    description: &str,
    policy: ControlEndpointPolicy,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {description}: {error}"))?;
    let group_matches = policy
        .socket_gid
        .is_none_or(|expected| metadata.gid() == expected);
    if !metadata.file_type().is_socket()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || !group_matches
        || metadata.mode() & 0o7777 != policy.socket_mode
    {
        return Err(format!("{description} has unsafe ownership or mode"));
    }
    Ok(())
}

#[cfg(unix)]
fn bind_private_control_socket(
    path: &Path,
    policy: ControlEndpointPolicy,
) -> Result<UnixListener, String> {
    let directory = path
        .parent()
        .ok_or_else(|| "control socket has no parent directory".to_string())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..16_u8 {
        let staging = directory.join(format!(
            ".p{:x}{:04x}{attempt:x}",
            std::process::id(),
            nonce & 0xffff
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&staging) {
            Ok(()) => {
                std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| {
                        let _ = std::fs::remove_dir(&staging);
                        format!(
                            "cannot secure control socket staging directory {}: {error}",
                            staging.display()
                        )
                    })?;
                return publish_control_socket(path, &staging, policy);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create control socket staging directory {}: {error}",
                    staging.display()
                ));
            }
        }
    }

    Err("cannot allocate a private control socket staging directory".to_string())
}

#[cfg(unix)]
fn publish_control_socket(
    path: &Path,
    staging: &Path,
    policy: ControlEndpointPolicy,
) -> Result<UnixListener, String> {
    let staged_path = staging.join("s");
    let listener = match UnixListener::bind(&staged_path) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = std::fs::remove_dir(staging);
            return Err(format!(
                "cannot bind staged control socket {}: {error}",
                staged_path.display()
            ));
        }
    };
    if let Some(group) = policy.socket_gid
        && let Err(error) =
            nix::unistd::chown(&staged_path, None, Some(nix::unistd::Gid::from_raw(group)))
    {
        remove_staged_control_socket(&staged_path, staging);
        return Err(format!(
            "cannot set staged control socket administration group: {error}"
        ));
    }
    if let Err(error) = std::fs::set_permissions(
        &staged_path,
        std::fs::Permissions::from_mode(policy.socket_mode),
    ) {
        remove_staged_control_socket(&staged_path, staging);
        return Err(format!("cannot secure staged control socket: {error}"));
    }
    if let Err(error) = validate_control_socket(&staged_path, "staged control socket", policy) {
        remove_staged_control_socket(&staged_path, staging);
        return Err(error);
    }

    if let Err(error) = std::fs::hard_link(&staged_path, path) {
        remove_staged_control_socket(&staged_path, staging);
        return Err(format!(
            "cannot atomically publish control socket {}: {error}",
            path.display()
        ));
    }
    if let Err(error) = std::fs::remove_file(&staged_path) {
        let _ = std::fs::remove_file(path);
        remove_staged_control_socket(&staged_path, staging);
        return Err(format!(
            "cannot remove staged control socket {}: {error}",
            staged_path.display()
        ));
    }
    if let Err(error) = std::fs::remove_dir(staging) {
        let _ = std::fs::remove_file(path);
        return Err(format!(
            "cannot remove control socket staging directory {}: {error}",
            staging.display()
        ));
    }

    if let Err(error) = validate_control_socket(path, "published control socket", policy) {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }

    Ok(listener)
}

#[cfg(unix)]
fn remove_staged_control_socket(path: &Path, directory: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(directory);
}

#[cfg(unix)]
enum ControlRequestError {
    TooLarge,
    Cancelled,
    Io(io::Error),
}

#[cfg(unix)]
fn read_control_request(
    stream: &mut UnixStream,
    shutdown: &IngressShutdown,
    deadline: Instant,
) -> Result<Vec<u8>, ControlRequestError> {
    let mut request = Vec::with_capacity(CONTROL_REQUEST_LIMIT as usize);
    loop {
        if shutdown.is_exiting() {
            return Err(ControlRequestError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(ControlRequestError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "control request exceeded its absolute deadline",
            )));
        }
        let mut chunk = [0_u8; 256];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(request),
            Ok(read) if request.len().saturating_add(read) > CONTROL_REQUEST_LIMIT as usize => {
                return Err(ControlRequestError::TooLarge);
            }
            Ok(read) => request.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(ControlRequestError::Io(error)),
        }
    }
}

#[cfg(unix)]
fn write_control_response(
    stream: &mut UnixStream,
    mut response: &[u8],
    shutdown: &IngressShutdown,
    deadline: Instant,
) -> io::Result<()> {
    while !response.is_empty() {
        if shutdown.is_exiting() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "control response cancelled during shutdown",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control request exceeded its absolute deadline",
            ));
        }
        match stream.write(response) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "control response socket stopped accepting bytes",
                ));
            }
            Ok(written) => response = &response[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn start_control_server(
    state: Arc<ProxyState>,
    shutdown: IngressShutdown,
) -> Result<(PathBuf, thread::JoinHandle<()>), String> {
    let path = state.control_socket_path();
    let directory = path
        .parent()
        .ok_or_else(|| "control socket has no parent directory".to_string())?;
    let policy = if let Some(paths) = &state.production_paths {
        if state
            .public_snapshot()
            .is_some_and(|snapshot| snapshot.intent_owner == IntentOwner::Root)
        {
            paths.validate_control_group()?;
        }
        let (prepared_directory, admin_gid) = paths.ensure_control_directory()?;
        debug_assert_eq!(prepared_directory, directory);
        ControlEndpointPolicy::public(admin_gid)
    } else {
        crate::production_paths::ensure_owned_directory(
            directory,
            "development control directory",
            0o700,
        )?;
        ControlEndpointPolicy::development()
    };

    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            validate_control_socket(&path, "existing control socket", policy)
                .map_err(|error| format!("{error}: {}", path.display()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect control socket {}: {error}",
                path.display()
            ));
        }
    }
    if std::fs::symlink_metadata(&path).is_ok() {
        if UnixStream::connect(&path).is_ok() {
            return Err(format!(
                "another TLS proxy daemon is already using {}",
                path.display()
            ));
        }
        std::fs::remove_file(&path)
            .map_err(|error| format!("cannot remove stale control socket: {error}"))?;
    }

    let listener = bind_private_control_socket(&path, policy)?;
    validate_control_socket(&path, "bound control socket", policy)?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("cannot configure control socket: {error}"))?;

    let thread = thread::spawn(move || {
        while !shutdown.is_exiting() {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Err(error) = stream.set_read_timeout(Some(CONTROL_IO_POLL_INTERVAL)) {
                        let _ = writeln!(stream, "ERROR cannot configure request timeout: {error}");
                        continue;
                    }
                    if let Err(error) = stream.set_write_timeout(Some(CONTROL_IO_POLL_INTERVAL)) {
                        let _ =
                            writeln!(stream, "ERROR cannot configure response timeout: {error}");
                        continue;
                    }
                    let deadline = Instant::now()
                        .checked_add(CONTROL_IO_TIMEOUT)
                        .unwrap_or_else(Instant::now);
                    let peer = match control_peer(&stream) {
                        Ok(peer) => peer,
                        Err(_) => {
                            let _ = stream.write_all(b"ERROR control peer authentication failed\n");
                            continue;
                        }
                    };
                    let response = match read_control_request(&mut stream, &shutdown, deadline) {
                        Err(ControlRequestError::TooLarge) => format!(
                            "ERROR request exceeds the {CONTROL_REQUEST_LIMIT} byte limit\n"
                        ),
                        Err(ControlRequestError::Cancelled) => continue,
                        Err(ControlRequestError::Io(error)) => {
                            format!("ERROR cannot read request: {error}\n")
                        }
                        Ok(request) => match String::from_utf8(request) {
                            Ok(request) => {
                                let request = request.trim();
                                match control_command_access(request) {
                                    Some(access) if policy.authorizes(peer, access) => {
                                        render_control_response(&state, &shutdown, request)
                                    }
                                    Some(_) => {
                                        "ERROR control command is not authorized\n".to_string()
                                    }
                                    None => "ERROR unknown command\n".to_string(),
                                }
                            }
                            Err(_) => "ERROR request is not valid UTF-8\n".to_string(),
                        },
                    };
                    let _ = write_control_response(
                        &mut stream,
                        response.as_bytes(),
                        &shutdown,
                        deadline,
                    );
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

struct RouteSummary {
    hosting_profile: &'static str,
    config_generation: u64,
    declared_routes: usize,
    required_routes: usize,
    optional_routes: usize,
    active_routes: usize,
    degraded_routes: usize,
    ready: bool,
}

fn route_summary(state: &ProxyState) -> RouteSummary {
    let profile = state.hosting_profile();
    route_summary_for_profile(state, &profile)
}

fn route_summary_for_profile(state: &ProxyState, profile: &HostingProfile) -> RouteSummary {
    let routes = state
        .routes
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(snapshot) = profile.public_snapshot() else {
        return RouteSummary {
            hosting_profile: profile.name(),
            config_generation: 0,
            declared_routes: 0,
            required_routes: 0,
            optional_routes: 0,
            active_routes: routes.len(),
            degraded_routes: 0,
            ready: true,
        };
    };

    let now_unix_seconds = current_unix_seconds();
    let active_hostnames = routes
        .iter()
        .filter_map(|(hostname, active)| {
            let declaration = snapshot.routes.get(hostname)?;
            (active.declaration_generation == Some(snapshot.generation)
                && declaration.workload == active.backend.project
                && declaration.role == active.backend.role
                && active.certificate_is_valid_at(now_unix_seconds))
            .then_some(hostname)
        })
        .collect::<BTreeSet<_>>();
    let required_routes = snapshot
        .routes
        .values()
        .filter(|declaration| declaration.required)
        .count();
    let active_required_routes = snapshot
        .routes
        .iter()
        .filter(|(hostname, declaration)| {
            declaration.required && active_hostnames.contains(hostname)
        })
        .count();
    let active_routes = active_hostnames.len();

    RouteSummary {
        hosting_profile: profile.name(),
        config_generation: snapshot.generation,
        declared_routes: snapshot.routes.len(),
        required_routes,
        optional_routes: snapshot.routes.len().saturating_sub(required_routes),
        active_routes,
        degraded_routes: snapshot.routes.len().saturating_sub(active_routes),
        ready: active_required_routes == required_routes
            && state.registry_valid.load(Ordering::Acquire),
    }
}

#[derive(Serialize)]
struct DegradedRouteStatus {
    hostname: String,
    workload: String,
    role: String,
    required: bool,
    reason: &'static str,
}

#[derive(Serialize)]
struct DeclaredCertificateStatus {
    hostname: String,
    workload: String,
    role: String,
    required: bool,
    not_after_unix_seconds: u64,
    expiry_state: &'static str,
}

#[derive(Serialize)]
struct CapacityStatus {
    in_use: usize,
    limit: usize,
}

#[derive(Serialize)]
struct ControlAdmissionStatus {
    active_connections: CapacityStatus,
    pre_routing_connections: CapacityStatus,
    relay_connections: CapacityStatus,
    handoff_negotiations: CapacityStatus,
    accepts_per_second_limit: usize,
    accept_burst_limit: usize,
    source_entries: CapacityStatus,
    source_accepts_per_second_limit: usize,
    source_accept_burst_limit: usize,
    source_pre_routing_limit: usize,
    source_ipv6_prefix: u8,
    source_entry_ttl_seconds: u64,
    source_policy_overrides: usize,
}

#[derive(Serialize)]
struct ControlActivityStatus {
    queued_route_selections: usize,
    route_selection_queue_limit: usize,
    route_selection_workers: usize,
    queued_connections: usize,
    connection_queue_limit: usize,
    connection_workers: usize,
    waiting_clients: usize,
    inflight_discoveries: usize,
    active_probes: usize,
}

#[derive(Serialize)]
struct ControlConfigurationStatus {
    registry_valid: bool,
    undeclared_registrations: usize,
    rejected_registry_snapshots: u64,
    accepted_config_reloads: u64,
    rejected_config_reloads: u64,
    last_rejected_generation: Option<u64>,
    last_reload_error: Option<&'static str>,
    conflicts: usize,
}

#[derive(Serialize)]
struct ControlCounterStatus {
    accepted_connections: u64,
    relayed_connections: u64,
    completed_relays: u64,
    failed_relays: u64,
    relay_idle_timeouts: u64,
    relay_backend_connect_failures: u64,
    relay_client_to_workload_bytes: u64,
    relay_workload_to_client_bytes: u64,
    relay_duration_nanoseconds: u64,
    rejected_connections: u64,
    rejected_accept_rate: u64,
    rejected_global_capacity: u64,
    rejected_source_rate: u64,
    rejected_source_concurrency: u64,
    rejected_source_state_capacity: u64,
    rejected_pre_routing_capacity: u64,
    rejected_relay_capacity: u64,
    rejected_routing_queue: u64,
    rejected_routing_timeout: u64,
    rejected_worker_queue: u64,
    successful_discoveries: u64,
    handoff_attempts: u64,
    successful_handoffs: u64,
    handoff_fallbacks: u64,
    handoff_capacity_skips: u64,
    delivered_handoff_failures: u64,
    conflict_capacity_drops: u64,
    route_capacity_rejections: u64,
}

#[derive(Serialize)]
struct ControlJsonStatus {
    schema_version: u32,
    live: bool,
    draining: bool,
    ready: bool,
    hosting_profile: &'static str,
    generation: u64,
    listeners: Vec<String>,
    declared_routes: usize,
    required_routes: usize,
    optional_routes: usize,
    active_routes: usize,
    degraded_route_count: usize,
    degraded_routes: Vec<DegradedRouteStatus>,
    degraded_routes_omitted: usize,
    certificate_route_count: usize,
    certificate_routes: Vec<DeclaredCertificateStatus>,
    certificate_routes_omitted: usize,
    configuration: ControlConfigurationStatus,
    admission: ControlAdmissionStatus,
    activity: ControlActivityStatus,
    counters: ControlCounterStatus,
}

fn degraded_route_statuses(
    state: &ProxyState,
    profile: &HostingProfile,
) -> Vec<DegradedRouteStatus> {
    let Some(snapshot) = profile.public_snapshot() else {
        return Vec::new();
    };
    let now_unix_seconds = current_unix_seconds();
    let (active_hostnames, expired_hostnames) = state
        .routes
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .fold(
            (BTreeSet::new(), BTreeSet::new()),
            |(mut active_hostnames, mut expired_hostnames), (hostname, active)| {
                if snapshot.routes.get(hostname).is_some_and(|declaration| {
                    active.declaration_generation == Some(snapshot.generation)
                        && declaration.workload == active.backend.project
                        && declaration.role == active.backend.role
                }) {
                    if active.certificate_is_valid_at(now_unix_seconds) {
                        active_hostnames.insert(hostname.clone());
                    } else {
                        expired_hostnames.insert(hostname.clone());
                    }
                }
                (active_hostnames, expired_hostnames)
            },
        );
    let failures = state
        .route_failures
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let conflicts = state
        .conflicts
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    snapshot
        .routes
        .iter()
        .filter(|(hostname, _)| !active_hostnames.contains(*hostname))
        .take(MAX_ROUTE_DIAGNOSTICS)
        .map(|(hostname, declaration)| {
            let reason = if conflicts.contains(hostname) {
                "conflict"
            } else if expired_hostnames.contains(hostname) {
                RouteFailure::CertificateExpired.label()
            } else {
                failures
                    .get(hostname)
                    .copied()
                    .map(RouteFailure::label)
                    .unwrap_or("pending")
            };
            DegradedRouteStatus {
                hostname: hostname.clone(),
                workload: declaration.workload.clone(),
                role: declaration.role.clone(),
                required: declaration.required,
                reason,
            }
        })
        .collect()
}

fn declared_certificate_statuses(
    state: &ProxyState,
    profile: &HostingProfile,
) -> (usize, Vec<DeclaredCertificateStatus>) {
    let Some(snapshot) = profile.public_snapshot() else {
        return (0, Vec::new());
    };
    let now_unix_seconds = current_unix_seconds();
    let routes = state
        .routes
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut count = 0;
    let statuses = snapshot
        .routes
        .iter()
        .filter_map(|(hostname, declaration)| {
            let active = routes.get(hostname)?;
            if active.declaration_generation != Some(snapshot.generation)
                || declaration.workload != active.backend.project
                || declaration.role != active.backend.role
            {
                return None;
            }
            count += 1;
            (count <= MAX_ROUTE_DIAGNOSTICS).then(|| DeclaredCertificateStatus {
                hostname: hostname.clone(),
                workload: declaration.workload.clone(),
                role: declaration.role.clone(),
                required: declaration.required,
                not_after_unix_seconds: active.certificate.not_after_unix_seconds,
                expiry_state: active.certificate.expiry_state_at(now_unix_seconds).label(),
            })
        })
        .collect();
    (count, statuses)
}

fn render_json_control_status(state: &ProxyState, shutdown: &IngressShutdown) -> String {
    let profile = state.hosting_profile();
    let route_summary = route_summary_for_profile(state, &profile);
    let degraded_routes = degraded_route_statuses(state, &profile);
    let (certificate_route_count, certificate_routes) =
        declared_certificate_statuses(state, &profile);
    let admission = state.admission.snapshot();
    let mut listeners = state
        .listeners
        .read()
        .map(|listeners| {
            listeners
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    listeners.sort();
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
    let reload_status = state
        .config_reload_status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let status = ControlJsonStatus {
        schema_version: CONTROL_SCHEMA_VERSION,
        live: true,
        draining: shutdown.is_requested(),
        ready: route_summary.ready && !shutdown.is_requested(),
        hosting_profile: route_summary.hosting_profile,
        generation: route_summary.config_generation,
        listeners,
        declared_routes: route_summary.declared_routes,
        required_routes: route_summary.required_routes,
        optional_routes: route_summary.optional_routes,
        active_routes: route_summary.active_routes,
        degraded_route_count: route_summary.degraded_routes,
        degraded_routes,
        degraded_routes_omitted: route_summary
            .degraded_routes
            .saturating_sub(MAX_ROUTE_DIAGNOSTICS),
        certificate_route_count,
        certificate_routes_omitted: certificate_route_count.saturating_sub(MAX_ROUTE_DIAGNOSTICS),
        certificate_routes,
        configuration: ControlConfigurationStatus {
            registry_valid: state.registry_valid.load(Ordering::Acquire),
            undeclared_registrations: state.undeclared_registrations.load(Ordering::Acquire),
            rejected_registry_snapshots: state.rejected_registry_snapshots.load(Ordering::Acquire),
            accepted_config_reloads: reload_status.accepted_reloads,
            rejected_config_reloads: reload_status.rejected_reloads,
            last_rejected_generation: reload_status.last_rejected_generation,
            last_reload_error: reload_status.last_error.map(ConfigReloadError::label),
            conflicts,
        },
        admission: ControlAdmissionStatus {
            active_connections: CapacityStatus {
                in_use: admission.global.in_use,
                limit: admission.global.limit,
            },
            pre_routing_connections: CapacityStatus {
                in_use: admission.pre_routing.in_use,
                limit: admission.pre_routing.limit,
            },
            relay_connections: CapacityStatus {
                in_use: admission.relay.in_use,
                limit: admission.relay.limit,
            },
            handoff_negotiations: CapacityStatus {
                in_use: admission.handoff.in_use,
                limit: admission.handoff.limit,
            },
            accepts_per_second_limit: state.limits.accepts_per_second(),
            accept_burst_limit: state.limits.accept_burst(),
            source_entries: CapacityStatus {
                in_use: admission.source_entries,
                limit: admission.source_entry_limit,
            },
            source_accepts_per_second_limit: state.limits.source().accepts_per_second,
            source_accept_burst_limit: state.limits.source().accept_burst,
            source_pre_routing_limit: state.limits.source().pre_routing_connections,
            source_ipv6_prefix: state.limits.source().ipv6_prefix,
            source_entry_ttl_seconds: state.limits.source().entry_ttl_seconds,
            source_policy_overrides: state.limits.source().overrides.len(),
        },
        activity: ControlActivityStatus {
            queued_route_selections: state.queued_route_selections.load(Ordering::Relaxed),
            route_selection_queue_limit: ROUTE_SELECTION_QUEUE_CAPACITY,
            route_selection_workers: ROUTE_SELECTION_WORKERS,
            queued_connections: state.queued_connections.load(Ordering::Relaxed),
            connection_queue_limit: state.limits.handoff_workers(),
            connection_workers: state.limits.handoff_workers(),
            waiting_clients: state.waiting_clients.load(Ordering::Relaxed),
            inflight_discoveries: discoveries,
            active_probes: probes,
        },
        counters: ControlCounterStatus {
            accepted_connections: state.accepted_connections.load(Ordering::Relaxed),
            relayed_connections: state.relayed_connections.load(Ordering::Relaxed),
            completed_relays: state.completed_relays.load(Ordering::Relaxed),
            failed_relays: state.failed_relays.load(Ordering::Relaxed),
            relay_idle_timeouts: state.relay_idle_timeouts.load(Ordering::Relaxed),
            relay_backend_connect_failures: state
                .relay_backend_connect_failures
                .load(Ordering::Relaxed),
            relay_client_to_workload_bytes: state
                .relay_client_to_workload_bytes
                .load(Ordering::Relaxed),
            relay_workload_to_client_bytes: state
                .relay_workload_to_client_bytes
                .load(Ordering::Relaxed),
            relay_duration_nanoseconds: state.relay_duration_nanoseconds.load(Ordering::Relaxed),
            rejected_connections: state.rejected_connections.load(Ordering::Relaxed),
            rejected_accept_rate: state.rejected_accept_rate.load(Ordering::Relaxed),
            rejected_global_capacity: state.rejected_global_capacity.load(Ordering::Relaxed),
            rejected_source_rate: state.rejected_source_rate.load(Ordering::Relaxed),
            rejected_source_concurrency: state.rejected_source_concurrency.load(Ordering::Relaxed),
            rejected_source_state_capacity: state
                .rejected_source_state_capacity
                .load(Ordering::Relaxed),
            rejected_pre_routing_capacity: state
                .rejected_pre_routing_capacity
                .load(Ordering::Relaxed),
            rejected_relay_capacity: state.rejected_relay_capacity.load(Ordering::Relaxed),
            rejected_routing_queue: state.rejected_routing_queue.load(Ordering::Relaxed),
            rejected_routing_timeout: state.rejected_routing_timeout.load(Ordering::Relaxed),
            rejected_worker_queue: state.rejected_worker_queue.load(Ordering::Relaxed),
            successful_discoveries: state.successful_discoveries.load(Ordering::Relaxed),
            handoff_attempts: state.handoff_attempts.load(Ordering::Relaxed),
            successful_handoffs: state.successful_handoffs.load(Ordering::Relaxed),
            handoff_fallbacks: state.handoff_fallbacks.load(Ordering::Relaxed),
            handoff_capacity_skips: state.handoff_capacity_skips.load(Ordering::Relaxed),
            delivered_handoff_failures: state.delivered_handoff_failures.load(Ordering::Relaxed),
            conflict_capacity_drops: state.conflict_capacity_drops.load(Ordering::Relaxed),
            route_capacity_rejections: state.route_capacity_rejections.load(Ordering::Relaxed),
        },
    };
    let mut rendered =
        serde_json::to_string(&status).expect("control status contains only JSON-safe values");
    rendered.push('\n');
    rendered
}

fn render_prometheus_metrics(state: &ProxyState, shutdown: &IngressShutdown) -> String {
    let profile = state.hosting_profile();
    let summary = route_summary_for_profile(state, &profile);
    let admission = state.admission.snapshot();
    let conflicts = state
        .conflicts
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reload_status = state
        .config_reload_status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut output = String::with_capacity(16 * 1024);
    macro_rules! metric {
        ($($argument:tt)*) => {
            writeln!(&mut output, $($argument)*)
                .expect("writing Prometheus metrics to a String cannot fail")
        };
    }

    metric!(
        "phx_port_build_info{{version=\"{}\"}} 1",
        prometheus_label(env!("CARGO_PKG_VERSION"))
    );
    metric!(
        "phx_port_ready {}",
        usize::from(summary.ready && !shutdown.is_requested())
    );
    metric!("phx_port_draining {}", usize::from(shutdown.is_requested()));
    metric!("phx_port_config_generation {}", summary.config_generation);
    for (route_state, value) in [
        ("declared", summary.declared_routes),
        ("required", summary.required_routes),
        ("optional", summary.optional_routes),
        ("active", summary.active_routes),
        ("degraded", summary.degraded_routes),
        ("conflict", conflicts.len()),
    ] {
        metric!("phx_port_routes{{state=\"{route_state}\"}} {value}");
    }
    for (stage, in_use, limit) in [
        ("active", admission.global.in_use, admission.global.limit),
        (
            "pre_routing",
            admission.pre_routing.in_use,
            admission.pre_routing.limit,
        ),
        ("relay", admission.relay.in_use, admission.relay.limit),
        ("handoff", admission.handoff.in_use, admission.handoff.limit),
    ] {
        metric!("phx_port_admission_in_use{{stage=\"{stage}\"}} {in_use}");
        metric!("phx_port_admission_limit{{stage=\"{stage}\"}} {limit}");
    }
    metric!(
        "phx_port_source_entries{{state=\"in_use\"}} {}",
        admission.source_entries
    );
    metric!(
        "phx_port_source_entries{{state=\"limit\"}} {}",
        admission.source_entry_limit
    );
    metric!(
        "phx_port_route_selection_queue{{state=\"in_use\"}} {}",
        state.queued_route_selections.load(Ordering::Relaxed)
    );
    metric!(
        "phx_port_route_selection_queue{{state=\"limit\"}} {}",
        ROUTE_SELECTION_QUEUE_CAPACITY
    );
    metric!(
        "phx_port_delivery_queue{{state=\"in_use\"}} {}",
        state.queued_connections.load(Ordering::Relaxed)
    );
    metric!(
        "phx_port_delivery_queue{{state=\"limit\"}} {}",
        state.limits.handoff_workers()
    );
    metric!(
        "phx_port_connections_total{{outcome=\"accepted\"}} {}",
        state.accepted_connections.load(Ordering::Relaxed)
    );
    metric!(
        "phx_port_connections_total{{outcome=\"rejected\"}} {}",
        state.rejected_connections.load(Ordering::Relaxed)
    );
    for (reason, value) in [
        (
            "accept_rate",
            state.rejected_accept_rate.load(Ordering::Relaxed),
        ),
        (
            "global_capacity",
            state.rejected_global_capacity.load(Ordering::Relaxed),
        ),
        (
            "source_rate",
            state.rejected_source_rate.load(Ordering::Relaxed),
        ),
        (
            "source_concurrency",
            state.rejected_source_concurrency.load(Ordering::Relaxed),
        ),
        (
            "source_state_capacity",
            state.rejected_source_state_capacity.load(Ordering::Relaxed),
        ),
        (
            "pre_routing_capacity",
            state.rejected_pre_routing_capacity.load(Ordering::Relaxed),
        ),
        (
            "relay_capacity",
            state.rejected_relay_capacity.load(Ordering::Relaxed),
        ),
        (
            "routing_queue",
            state.rejected_routing_queue.load(Ordering::Relaxed),
        ),
        (
            "routing_timeout",
            state.rejected_routing_timeout.load(Ordering::Relaxed),
        ),
        (
            "worker_queue",
            state.rejected_worker_queue.load(Ordering::Relaxed),
        ),
    ] {
        metric!("phx_port_admission_rejections_total{{reason=\"{reason}\"}} {value}");
    }
    for (outcome, value) in [
        ("attempt", state.handoff_attempts.load(Ordering::Relaxed)),
        ("success", state.successful_handoffs.load(Ordering::Relaxed)),
        ("fallback", state.handoff_fallbacks.load(Ordering::Relaxed)),
        (
            "capacity_skip",
            state.handoff_capacity_skips.load(Ordering::Relaxed),
        ),
        (
            "post_delivery_failure",
            state.delivered_handoff_failures.load(Ordering::Relaxed),
        ),
    ] {
        metric!("phx_port_handoffs_total{{outcome=\"{outcome}\"}} {value}");
    }
    for (outcome, value) in [
        ("started", state.relayed_connections.load(Ordering::Relaxed)),
        ("completed", state.completed_relays.load(Ordering::Relaxed)),
        ("failed", state.failed_relays.load(Ordering::Relaxed)),
    ] {
        metric!("phx_port_relays_total{{outcome=\"{outcome}\"}} {value}");
    }
    for (direction, value) in [
        (
            "client_to_workload",
            state.relay_client_to_workload_bytes.load(Ordering::Relaxed),
        ),
        (
            "workload_to_client",
            state.relay_workload_to_client_bytes.load(Ordering::Relaxed),
        ),
    ] {
        metric!("phx_port_relay_bytes_total{{direction=\"{direction}\"}} {value}");
    }
    let relay_duration_nanoseconds = state.relay_duration_nanoseconds.load(Ordering::Relaxed);
    metric!(
        "phx_port_relay_duration_seconds_total {}.{:09}",
        relay_duration_nanoseconds / 1_000_000_000,
        relay_duration_nanoseconds % 1_000_000_000
    );
    metric!(
        "phx_port_relay_idle_timeouts_total {}",
        state.relay_idle_timeouts.load(Ordering::Relaxed)
    );
    metric!(
        "phx_port_relay_backend_connect_failures_total {}",
        state.relay_backend_connect_failures.load(Ordering::Relaxed)
    );
    for (outcome, value) in [
        ("accepted", reload_status.accepted_reloads),
        ("rejected", reload_status.rejected_reloads),
    ] {
        metric!("phx_port_config_reloads_total{{outcome=\"{outcome}\"}} {value}");
    }
    metric!(
        "phx_port_registry_valid {}",
        usize::from(state.registry_valid.load(Ordering::Acquire))
    );
    metric!(
        "phx_port_registry_rejected_snapshots_total {}",
        state.rejected_registry_snapshots.load(Ordering::Acquire)
    );
    metric!(
        "phx_port_undeclared_registrations {}",
        state.undeclared_registrations.load(Ordering::Acquire)
    );
    metric!(
        "phx_port_route_conflict_capacity_drops_total {}",
        state.conflict_capacity_drops.load(Ordering::Acquire)
    );
    metric!(
        "phx_port_route_capacity_rejections_total {}",
        state.route_capacity_rejections.load(Ordering::Acquire)
    );
    metric!(
        "phx_port_discoveries_total{{outcome=\"success\"}} {}",
        state.successful_discoveries.load(Ordering::Relaxed)
    );
    let source_diagnostics_enabled = profile
        .public_snapshot()
        .and_then(|snapshot| snapshot.source_diagnostics)
        .is_some_and(|diagnostics| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .is_ok_and(|now| diagnostics.active_at(now.as_secs()))
        });
    metric!(
        "phx_port_source_diagnostics_enabled {}",
        usize::from(source_diagnostics_enabled)
    );

    if let Some(snapshot) = profile.public_snapshot() {
        let routes = state
            .routes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let failures = state
            .route_failures
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now_unix_seconds = current_unix_seconds();
        for (hostname, declaration) in &snapshot.routes {
            let active = routes.get(hostname).filter(|active| {
                active.declaration_generation == Some(snapshot.generation)
                    && active.backend.project == declaration.workload
                    && active.backend.role == declaration.role
            });
            let route_state = if let Some(active) = active {
                if active.certificate_is_valid_at(now_unix_seconds) {
                    "active"
                } else {
                    RouteFailure::CertificateExpired.label()
                }
            } else if conflicts.contains_key(hostname) {
                "conflict"
            } else {
                failures
                    .get(hostname)
                    .copied()
                    .map(RouteFailure::label)
                    .unwrap_or("pending")
            };
            metric!(
                "phx_port_route_state{{hostname=\"{}\",workload=\"{}\",role=\"{}\",required=\"{}\",state=\"{route_state}\"}} 1",
                prometheus_label(hostname),
                prometheus_label(&declaration.workload),
                prometheus_label(&declaration.role),
                declaration.required
            );
            if let Some(active) = active {
                metric!(
                    "phx_port_route_certificate_not_after_seconds{{hostname=\"{}\",expiry_state=\"{}\"}} {}",
                    prometheus_label(hostname),
                    active.certificate.expiry_state_at(now_unix_seconds).label(),
                    active.certificate.not_after_unix_seconds
                );
            }
        }
    }
    output
}

fn prometheus_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn render_control_response(
    state: &ProxyState,
    shutdown: &IngressShutdown,
    request: &str,
) -> String {
    match request {
        "STATUS" => {
            let admission = state.admission.snapshot();
            let route_summary = route_summary(state);
            let draining = shutdown.is_requested();
            let lifecycle = if draining { "draining" } else { "running" };
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
            let reload_status = state
                .config_reload_status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let last_reload_error = reload_status
                .last_error
                .map(ConfigReloadError::label)
                .unwrap_or("none");
            let last_rejected_config_generation =
                reload_status.last_rejected_generation.unwrap_or(0);
            format!(
                "{lifecycle}\nhosting_profile={hosting_profile}\nconfig_generation={config_generation}\ndeclared_routes={declared_routes}\nrequired_routes={required_routes}\noptional_routes={optional_routes}\nactive_routes={active_routes}\ndegraded_routes={degraded_routes}\ndraining={draining}\nready={ready}\nregistry_valid={registry_valid}\nundeclared_registrations={undeclared_registrations}\nrejected_registry_snapshots={rejected_registry_snapshots}\naccepted_config_reloads={accepted_config_reloads}\nrejected_config_reloads={rejected_config_reloads}\nlast_rejected_config_generation={last_rejected_config_generation}\nlast_reload_error={last_reload_error}\nlisteners={listeners}\nconflicts={conflicts}\nconflict_capacity_drops={conflict_capacity_drops}\nroute_capacity_rejections={route_capacity_rejections}\nactive_connections={active_connections}\nactive_connection_limit={active_connection_limit}\npre_routing_connections={pre_routing_connections}\npre_routing_connection_limit={pre_routing_connection_limit}\nactive_relays={active_relays}\nrelay_connection_limit={relay_connection_limit}\nhandoff_negotiations={handoff_negotiations}\nhandoff_negotiation_limit={handoff_negotiation_limit}\naccepts_per_second_limit={accepts_per_second_limit}\naccept_burst_limit={accept_burst_limit}\nsource_entries={source_entries}\nsource_entry_limit={source_entry_limit}\nsource_accepts_per_second_limit={source_accepts_per_second_limit}\nsource_accept_burst_limit={source_accept_burst_limit}\nsource_pre_routing_limit={source_pre_routing_limit}\nsource_ipv6_prefix={source_ipv6_prefix}\nsource_entry_ttl_seconds={source_entry_ttl_seconds}\nsource_policy_overrides={source_policy_overrides}\nqueued_route_selections={queued_route_selections}\nroute_selection_queue_limit={ROUTE_SELECTION_QUEUE_CAPACITY}\nroute_selection_workers={ROUTE_SELECTION_WORKERS}\nqueued_connections={queued_connections}\nconnection_queue_limit={connection_queue_limit}\nconnection_workers={connection_workers}\nwaiting_clients={waiting_clients}\ninflight_discoveries={discoveries}\nactive_probes={probes}\naccepted_connections={accepted_connections}\nrelayed_connections={relayed_connections}\ncompleted_relays={completed_relays}\nfailed_relays={failed_relays}\nrelay_idle_timeouts={relay_idle_timeouts}\nrelay_backend_connect_failures={relay_backend_connect_failures}\nrelay_client_to_workload_bytes={relay_client_to_workload_bytes}\nrelay_workload_to_client_bytes={relay_workload_to_client_bytes}\nrelay_duration_nanoseconds={relay_duration_nanoseconds}\nrejected_connections={rejected_connections}\nrejected_accept_rate={rejected_accept_rate}\nrejected_global_capacity={rejected_global_capacity}\nrejected_source_rate={rejected_source_rate}\nrejected_source_concurrency={rejected_source_concurrency}\nrejected_source_state_capacity={rejected_source_state_capacity}\nrejected_pre_routing_capacity={rejected_pre_routing_capacity}\nrejected_relay_capacity={rejected_relay_capacity}\nrejected_routing_queue={rejected_routing_queue}\nrejected_routing_timeout={rejected_routing_timeout}\nrejected_worker_queue={rejected_worker_queue}\nsuccessful_discoveries={successful_discoveries}\nhandoff_attempts={handoff_attempts}\nsuccessful_handoffs={successful_handoffs}\nhandoff_fallbacks={handoff_fallbacks}\nhandoff_capacity_skips={handoff_capacity_skips}\ndelivered_handoff_failures={delivered_handoff_failures}\n",
                lifecycle = lifecycle,
                hosting_profile = route_summary.hosting_profile,
                config_generation = route_summary.config_generation,
                declared_routes = route_summary.declared_routes,
                required_routes = route_summary.required_routes,
                optional_routes = route_summary.optional_routes,
                active_routes = route_summary.active_routes,
                degraded_routes = route_summary.degraded_routes,
                draining = draining,
                ready = route_summary.ready && !draining,
                registry_valid = state.registry_valid.load(Ordering::Acquire),
                undeclared_registrations = state.undeclared_registrations.load(Ordering::Acquire),
                rejected_registry_snapshots =
                    state.rejected_registry_snapshots.load(Ordering::Acquire),
                accepted_config_reloads = reload_status.accepted_reloads,
                rejected_config_reloads = reload_status.rejected_reloads,
                conflict_capacity_drops = state.conflict_capacity_drops.load(Ordering::Relaxed),
                route_capacity_rejections = state.route_capacity_rejections.load(Ordering::Relaxed),
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
                queued_route_selections = state.queued_route_selections.load(Ordering::Relaxed),
                queued_connections = state.queued_connections.load(Ordering::Relaxed),
                connection_queue_limit = state.limits.handoff_workers(),
                connection_workers = state.limits.handoff_workers(),
                waiting_clients = state.waiting_clients.load(Ordering::Relaxed),
                accepted_connections = state.accepted_connections.load(Ordering::Relaxed),
                relayed_connections = state.relayed_connections.load(Ordering::Relaxed),
                completed_relays = state.completed_relays.load(Ordering::Relaxed),
                failed_relays = state.failed_relays.load(Ordering::Relaxed),
                relay_idle_timeouts = state.relay_idle_timeouts.load(Ordering::Relaxed),
                relay_backend_connect_failures =
                    state.relay_backend_connect_failures.load(Ordering::Relaxed),
                relay_client_to_workload_bytes =
                    state.relay_client_to_workload_bytes.load(Ordering::Relaxed),
                relay_workload_to_client_bytes =
                    state.relay_workload_to_client_bytes.load(Ordering::Relaxed),
                relay_duration_nanoseconds =
                    state.relay_duration_nanoseconds.load(Ordering::Relaxed),
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
                rejected_routing_queue = state.rejected_routing_queue.load(Ordering::Relaxed),
                rejected_routing_timeout = state.rejected_routing_timeout.load(Ordering::Relaxed),
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
        "STATUS JSON" | "CHECK LIVE" | "CHECK READY" => render_json_control_status(state, shutdown),
        "ROUTES" => {
            let profile = state.hosting_profile();
            let public_snapshot = profile.public_snapshot();
            let mut lines = Vec::new();
            let mut active_hostnames = BTreeSet::new();
            let mut expired_hostnames = BTreeSet::new();
            let now_unix_seconds = current_unix_seconds();
            if let Ok(routes) = state.routes.read() {
                for (hostname, route) in routes.iter() {
                    if let Some(snapshot) = public_snapshot.as_ref() {
                        let Some(declaration) = snapshot.routes.get(hostname) else {
                            continue;
                        };
                        if route.declaration_generation != Some(snapshot.generation)
                            || declaration.workload != route.backend.project
                            || declaration.role != route.backend.role
                        {
                            continue;
                        }
                    }
                    let expiry_state = route.certificate.expiry_state_at(now_unix_seconds);
                    if expiry_state == CertificateExpiryState::Expired {
                        expired_hostnames.insert(hostname.clone());
                        continue;
                    }
                    active_hostnames.insert(hostname.clone());
                    lines.push(format!(
                        "active\t{hostname}\t{}\t{}\t{}\t{}\t{}\t{}",
                        route.backend.project,
                        route.backend.role,
                        route.backend.port,
                        route.certificate.fingerprint,
                        route.certificate.not_after_unix_seconds,
                        expiry_state.label()
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
            if let Some(snapshot) = public_snapshot {
                let failures = state
                    .route_failures
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for (hostname, declaration) in &snapshot.routes {
                    if active_hostnames.contains(hostname) {
                        continue;
                    }
                    let requirement = if declaration.required {
                        "required"
                    } else {
                        "optional"
                    };
                    let reason = if expired_hostnames.contains(hostname) {
                        RouteFailure::CertificateExpired.label()
                    } else {
                        failures
                            .get(hostname)
                            .copied()
                            .map(RouteFailure::label)
                            .unwrap_or("pending")
                    };
                    lines.push(format!(
                        "inactive\t{hostname}\t{}\t{}\t{requirement}\t{reason}",
                        declaration.workload, declaration.role
                    ));
                }
            }
            lines.sort();
            let omitted = lines.len().saturating_sub(MAX_ROUTE_DIAGNOSTICS);
            lines.truncate(MAX_ROUTE_DIAGNOSTICS);
            if omitted > 0 {
                lines.push(format!("truncated\t{omitted}"));
            }
            if lines.is_empty() {
                "No active TLS routes.\n".to_string()
            } else {
                format!("{}\n", lines.join("\n"))
            }
        }
        "RELOAD" if shutdown.is_requested() => {
            "ERROR reload is unavailable while ingress is draining\n".to_string()
        }
        "RELOAD" => match reload_public_profile(state) {
            ConfigReloadOutcome::NotPublic => {
                "ERROR reload requires the public Hosting Profile\n".to_string()
            }
            ConfigReloadOutcome::Unchanged(generation) => {
                format!("unchanged generation={generation}\n")
            }
            ConfigReloadOutcome::Accepted(generation) => {
                format!("reloaded generation={generation}\n")
            }
            ConfigReloadOutcome::Rejected(generation) => {
                format!("ERROR reload rejected generation={generation}\n")
            }
            ConfigReloadOutcome::Superseded(generation) => {
                format!("unchanged generation={generation}\n")
            }
        },
        "STOP" => {
            shutdown.request();
            "stopping\n".to_string()
        }
        _ => "ERROR unknown command\n".to_string(),
    }
}

#[cfg(test)]
fn handle_connection(
    client: TcpStream,
    source: IpAddr,
    accepted_at: Instant,
    state: Arc<ProxyState>,
    admission: PreRoutingAdmission,
) -> Result<(), String> {
    client
        .set_nonblocking(false)
        .map_err(|error| format!("cannot configure accepted client socket: {error}"))?;
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
    state.record_source_diagnostic(source, &hostname);
    client
        .set_read_timeout(None)
        .map_err(|error| format!("cannot clear ClientHello timeout before handoff: {error}"))?;

    let cached_backend = current_active_backend(&state, &hostname)?;
    let backend = if let Some(backend) = cached_backend.as_ref() {
        backend.clone()
    } else {
        resolve_backend(&hostname, &state)?
    };
    let relay_idle_timeout = state.relay_idle_timeout(&hostname);
    let handoff = HandoffJob {
        client,
        accepted_at,
        admission,
        hostname,
        peeked_length,
        backend,
        cached: cached_backend.is_some(),
        relay_idle_timeout,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(state.limits.handoff_workers())
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("cannot start test Tokio runtime: {error}"))?;
    match runtime.block_on(prepare_handoff(handoff, Arc::clone(&state)))? {
        None => Ok(()),
        Some(job) => {
            let (route_sender, _route_receiver) = mpsc::sync_channel(1);
            let ingress = TokioIngress {
                state,
                shutdown: IngressShutdown::new(DEVELOPMENT_SHUTDOWN_DRAIN_TIMEOUT),
                route_sender,
            };
            runtime.block_on(relay_tokio_connection(job, &ingress))
        }
    }
}

async fn prepare_handoff(
    handoff: HandoffJob,
    state: Arc<ProxyState>,
) -> Result<Option<RelayJob>, String> {
    let permit = match state.admission.try_acquire_handoff() {
        Ok(permit) => permit,
        Err(rejection) => {
            state.record_admission_rejection(rejection);
            state.record_delivery_outcome(DeliveryOutcome::HandoffCapacityUnavailable);
            return Ok(Some(handoff.into_relay()));
        }
    };
    let queued = QueuedConnection::new(Arc::clone(&state.queued_connections));
    // Cancellation may detach blocking work, so the closure owns the socket through the
    // irreversible PHXP outcome; only an awaited pre-delivery failure can return it for relay.
    tokio::task::spawn_blocking(move || {
        drop(queued);
        let _handoff_permit = permit;
        handoff
            .client
            .set_nonblocking(false)
            .map_err(|error| format!("cannot configure accepted client socket: {error}"))?;
        handoff
            .client
            .set_read_timeout(None)
            .map_err(|error| format!("cannot clear accepted client timeout: {error}"))?;
        perform_handoff(handoff, &state)
    })
    .await
    .map_err(|error| format!("blocking PHXP task failed: {error}"))?
}

fn perform_handoff(handoff: HandoffJob, state: &ProxyState) -> Result<Option<RelayJob>, String> {
    let HandoffJob {
        mut client,
        accepted_at,
        admission,
        hostname,
        peeked_length,
        backend,
        cached,
        relay_idle_timeout,
    } = handoff;
    let process_start = *PROCESS_START.get_or_init(Instant::now);
    let accepted_at_ns = accepted_at
        .saturating_duration_since(process_start)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let public_profile = state.public_snapshot().is_some();

    let mut connection_id = [0_u8; 16];
    match getrandom::fill(&mut connection_id) {
        Ok(()) => {
            let identity = if public_profile {
                handoff::EndpointIdentity::Production(&backend.project)
            } else {
                handoff::EndpointIdentity::Development(&backend.project)
            };
            state.handoff_attempts.fetch_add(1, Ordering::Relaxed);
            match handoff::try_transfer(
                client,
                identity,
                &backend.role,
                state.handoff_runtime.as_deref(),
                &hostname,
                peeked_length,
                connection_id,
                accepted_at_ns,
            ) {
                handoff::Outcome::Transferred => {
                    state.successful_handoffs.fetch_add(1, Ordering::Relaxed);
                    state.record_delivery_outcome(DeliveryOutcome::HandoffSuccess);
                    return Ok(None);
                }
                handoff::Outcome::Delivered(error) => {
                    state
                        .delivered_handoff_failures
                        .fetch_add(1, Ordering::Relaxed);
                    state.record_delivery_outcome(DeliveryOutcome::HandoffPostDeliveryFailure);
                    return Err(error);
                }
                handoff::Outcome::Unavailable(returned) => {
                    state.handoff_fallbacks.fetch_add(1, Ordering::Relaxed);
                    state.record_delivery_outcome(DeliveryOutcome::HandoffFallback);
                    client = returned;
                }
            }
        }
        Err(_) => {
            state.handoff_fallbacks.fetch_add(1, Ordering::Relaxed);
            state.record_delivery_outcome(DeliveryOutcome::HandoffFallback);
        }
    }

    Ok(Some(RelayJob {
        client,
        admission,
        hostname,
        backend,
        cached,
        idle_timeout: relay_idle_timeout,
    }))
}

impl HandoffJob {
    fn into_relay(self) -> RelayJob {
        RelayJob {
            client: self.client,
            admission: self.admission,
            hostname: self.hostname,
            backend: self.backend,
            cached: self.cached,
            idle_timeout: self.relay_idle_timeout,
        }
    }
}

async fn relay_tokio_connection(job: RelayJob, ingress: &TokioIngress) -> Result<(), String> {
    relay_tokio_connection_with_connector(job, ingress, |backend| async move {
        connect_tokio_backend(&backend).await
    })
    .await
}

async fn relay_tokio_connection_with_connector<Connect, Connecting>(
    job: RelayJob,
    ingress: &TokioIngress,
    connect_backend: Connect,
) -> Result<(), String>
where
    Connect: FnMut(Backend) -> Connecting,
    Connecting: Future<Output = io::Result<TokioTcpStream>>,
{
    let established = tokio::select! {
        biased;
        _ = ingress.shutdown.wait_requested() => return Ok(()),
        established = establish_relay(job, ingress, connect_backend) => established?,
    };
    let Some(mut established) = established else {
        return Ok(());
    };
    if !commit_relay_start(&ingress.state, &ingress.shutdown) {
        return Ok(());
    }

    let report = relay::copy_bidirectional(
        &mut established.client,
        &mut established.upstream,
        established.idle_timeout,
    )
    .await;
    ingress.state.record_relay_report(&report);
    match report.error {
        None => {
            ingress
                .state
                .completed_relays
                .fetch_add(1, Ordering::Relaxed);
            ingress
                .state
                .record_delivery_outcome(DeliveryOutcome::RelayCompleted);
            Ok(())
        }
        Some(error) => {
            if error.kind() == io::ErrorKind::TimedOut {
                ingress
                    .state
                    .relay_idle_timeouts
                    .fetch_add(1, Ordering::Relaxed);
            }
            ingress.state.failed_relays.fetch_add(1, Ordering::Relaxed);
            ingress
                .state
                .record_delivery_outcome(DeliveryOutcome::RelayFailed);
            Err(format!("relay failed: {error}"))
        }
    }
}

async fn establish_relay<Connect, Connecting>(
    job: RelayJob,
    ingress: &TokioIngress,
    mut connect_backend: Connect,
) -> Result<Option<EstablishedRelay>, String>
where
    Connect: FnMut(Backend) -> Connecting,
    Connecting: Future<Output = io::Result<TokioTcpStream>>,
{
    let RelayJob {
        client,
        admission,
        hostname,
        mut backend,
        cached,
        idle_timeout,
    } = job;
    let state = &ingress.state;
    let relay_permit = match acquire_relay_capacity(state) {
        Some(permit) => permit,
        None => return Ok(None),
    };
    let _relay_admission = admission.into_relay(relay_permit);

    client
        .set_nonblocking(true)
        .map_err(|error| format!("cannot return accepted socket to Tokio: {error}"))?;
    let client = TokioTcpStream::from_std(client)
        .map_err(|error| format!("cannot adopt accepted socket into Tokio: {error}"))?;
    let upstream = match connect_backend(backend.clone()).await {
        Ok(stream) => stream,
        Err(_) if cached => {
            state
                .relay_backend_connect_failures
                .fetch_add(1, Ordering::Relaxed);
            state
                .routes
                .write()
                .map_err(|_| "route table lock poisoned".to_string())?
                .remove(&hostname);
            backend = select_tokio_route(&hostname, ingress).await?.0;
            connect_backend(backend).await.map_err(|error| {
                state
                    .relay_backend_connect_failures
                    .fetch_add(1, Ordering::Relaxed);
                format!("verified backend disappeared: {error}")
            })?
        }
        Err(error) => {
            state
                .relay_backend_connect_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(format!("verified backend disappeared: {error}"));
        }
    };

    Ok(Some(EstablishedRelay {
        client,
        upstream,
        _admission: _relay_admission,
        idle_timeout,
    }))
}

fn commit_relay_start(state: &ProxyState, shutdown: &IngressShutdown) -> bool {
    shutdown.commit_if_running(|| {
        state.relayed_connections.fetch_add(1, Ordering::Relaxed);
        state.record_delivery_outcome(DeliveryOutcome::RelayStarted);
    })
}

async fn connect_tokio_backend(backend: &Backend) -> io::Result<TokioTcpStream> {
    let address: SocketAddr = ([127, 0, 0, 1], backend.port).into();
    tokio::time::timeout(BACKEND_CONNECT_TIMEOUT, TokioTcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend connection timed out"))?
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

fn ensure_before_route_deadline(deadline: Instant) -> Result<(), String> {
    route_deadline_remaining(deadline).map(|_| ())
}

fn route_deadline_remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "route selection timed out".to_string())
}

#[cfg(test)]
fn resolve_backend(hostname: &str, state: &ProxyState) -> Result<Backend, String> {
    resolve_backend_until(hostname, state, Instant::now() + DISCOVERY_TIMEOUT)
}

fn resolve_backend_until(
    hostname: &str,
    state: &ProxyState,
    deadline: Instant,
) -> Result<Backend, String> {
    ensure_before_route_deadline(deadline)?;
    if let Some(snapshot) = state.public_snapshot() {
        let declaration = snapshot
            .routes
            .get(hostname)
            .cloned()
            .ok_or_else(|| format!("public ingress has no Route Declaration for {hostname}"))?;
        let assignments = load_public_registry(state, &snapshot)?;
        ensure_before_route_deadline(deadline)?;
        let backend = match registered_declared_backend(&assignments, &declaration) {
            Ok(backend) => backend,
            Err(error) => {
                set_route_failure(state, hostname, RouteFailure::MissingRegistration);
                return Err(error);
            }
        };
        return state.discover_once_until(hostname, deadline, |deadline| {
            activate_declared_route_until(
                hostname,
                &declaration,
                snapshot.generation,
                backend,
                state,
                deadline,
            )
        });
    }
    let (route_cache_path, route_cache_storage) = state
        .route_cache()
        .expect("development mode has combined route storage");
    let cached = route_cache::load(route_cache_path, hostname, route_cache_storage)?;
    ensure_before_route_deadline(deadline)?;
    let candidates = candidate_backends_until(&state.config, cached.as_ref(), deadline);
    observe_workloads(state, &candidates);
    ensure_before_route_deadline(deadline)?;

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

    state.discover_once_until(hostname, deadline, |deadline| {
        discover_backend_until(hostname, state, candidates, deadline)
    })
}

fn activate_declared_route(
    hostname: &str,
    declaration: &RouteDeclaration,
    generation: u64,
    backend: Backend,
    state: &ProxyState,
) -> Result<Backend, String> {
    activate_declared_route_until(
        hostname,
        declaration,
        generation,
        backend,
        state,
        Instant::now() + DISCOVERY_TIMEOUT,
    )
}

fn activate_declared_route_until(
    hostname: &str,
    declaration: &RouteDeclaration,
    generation: u64,
    backend: Backend,
    state: &ProxyState,
    deadline: Instant,
) -> Result<Backend, String> {
    ensure_before_route_deadline(deadline)?;
    if declaration.hostname != hostname
        || declaration.workload != backend.project
        || declaration.role != backend.role
    {
        return Err("logical Workload registration does not match its declaration".to_string());
    }
    let certificate = probe_declared_backend_until(hostname, &backend, state, deadline)
        .inspect_err(|_| {
            set_route_failure(state, hostname, RouteFailure::VerificationFailed);
        })?;
    ensure_before_route_deadline(deadline)?;
    install_active_route(
        state,
        hostname,
        ProbeMatch {
            backend: backend.clone(),
            certificate,
        },
        Some(generation),
    )
    .inspect_err(|error| {
        if error.contains("capacity") {
            set_route_failure(state, hostname, RouteFailure::CapacityUnavailable);
        }
    })?;
    clear_route_failure(state, hostname);
    eprintln!(
        "event=route result=activated hostname={hostname} workload={} role={} backend_port={}",
        backend.project, backend.role, backend.port
    );
    Ok(backend)
}

fn probe_declared_backend_until(
    hostname: &str,
    backend: &Backend,
    state: &ProxyState,
    deadline: Instant,
) -> Result<CertificateProof, String> {
    ensure_before_route_deadline(deadline)?;
    let permit = state.probes.acquire(deadline).ok_or_else(|| {
        set_route_failure(state, hostname, RouteFailure::CapacityUnavailable);
        "certificate probe capacity unavailable".to_string()
    })?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let hostname = hostname.to_string();
    let backend = backend.clone();
    let connector = state.probe_connector_override.clone();
    thread::Builder::new()
        .name("phx-port-probe".to_string())
        .spawn(move || {
            let _permit = permit;
            let result = probe_backend_until(&hostname, &backend, connector.as_ref(), deadline);
            let _ = sender.send(result);
        })
        .map_err(|error| format!("cannot start bounded certificate probe: {error}"))?;

    receiver
        .recv_timeout(route_deadline_remaining(deadline)?)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => "route selection timed out".to_string(),
            mpsc::RecvTimeoutError::Disconnected => {
                "certificate probe stopped before returning a result".to_string()
            }
        })?
}

fn registered_declared_backend(
    assignments: &port_registry::LogicalAssignments,
    declaration: &RouteDeclaration,
) -> Result<Backend, String> {
    let port = assignments
        .get(&(declaration.workload.clone(), declaration.role.clone()))
        .copied()
        .ok_or_else(|| {
            format!(
                "declared Workload {}/{} has no registered loopback port",
                declaration.workload, declaration.role
            )
        })?;
    Ok(Backend {
        project: declaration.workload.clone(),
        role: declaration.role.clone(),
        port,
    })
}

fn load_public_registry(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
) -> Result<port_registry::LogicalAssignments, String> {
    let assignments = match port_registry::read_logical_assignments(&state.config) {
        Ok(assignments) => assignments,
        Err(error) => {
            record_registry_snapshot_failure(state);
            for hostname in snapshot.routes.keys() {
                set_route_failure(state, hostname, RouteFailure::RegistryInvalid);
            }
            return Err(format!(
                "cannot read logical Workload Port Registry: {error}"
            ));
        }
    };
    record_registry_snapshot_success(state);

    let declared_assignments = snapshot
        .routes
        .values()
        .map(|declaration| (declaration.workload.clone(), declaration.role.clone()))
        .collect::<BTreeSet<_>>();
    let undeclared = assignments
        .keys()
        .filter(|assignment| !declared_assignments.contains(*assignment))
        .count();
    state
        .undeclared_registrations
        .store(undeclared, Ordering::Release);
    state
        .route_failures
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|_, failure| *failure != RouteFailure::RegistryInvalid);
    Ok(assignments)
}

fn discover_backend(
    hostname: &str,
    state: &ProxyState,
    candidates: Vec<Backend>,
) -> Result<Backend, String> {
    discover_backend_until(
        hostname,
        state,
        candidates,
        Instant::now() + DISCOVERY_TIMEOUT,
    )
}

fn discover_backend_until(
    hostname: &str,
    state: &ProxyState,
    candidates: Vec<Backend>,
    deadline: Instant,
) -> Result<Backend, String> {
    let matches = probe_candidates_until(hostname, candidates, state, deadline);
    ensure_before_route_deadline(deadline)?;

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
    ensure_before_route_deadline(deadline)?;
    install_active_route(state, hostname, matched, None).inspect_err(|_| {
        cache_negative(state, hostname);
    })?;
    clear_conflict(state, hostname);
    state.successful_discoveries.fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "event=route result=discovered hostname={hostname} role={} backend_port={}",
        backend.role, backend.port
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
    let mut capacity_exhausted = false;
    let changed = if let Ok(mut conflicts) = state.conflicts.write() {
        if !conflicts.contains_key(hostname) && conflicts.len() >= MAX_ROUTE_CONFLICTS {
            capacity_exhausted = true;
            false
        } else if conflicts.get(hostname) == Some(&backends) {
            false
        } else {
            conflicts.insert(hostname.to_string(), backends.clone());
            true
        }
    } else {
        false
    };
    if capacity_exhausted {
        let _ = state.conflict_capacity_drops.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |count| Some(count.saturating_add(1)),
        );
    }
    if !changed {
        return;
    }
    eprintln!(
        "event=route result=conflict hostname={hostname} contenders={}",
        backends.len()
    );
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
    if let Some(snapshot) = state.public_snapshot() {
        reconcile_public_workloads(state, &snapshot);
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
                    && probe_backend(&hostname, &backend, state.probe_connector_override.as_ref())
                        .is_ok()
                {
                    record_conflict(state, &hostname, vec![incumbent.backend, backend.clone()]);
                }
                continue;
            }
            let Some((route_cache_path, route_cache_storage)) = state.route_cache() else {
                continue;
            };
            let cached = match route_cache::load(route_cache_path, &hostname, route_cache_storage) {
                Ok(cached) => cached,
                Err(_) => {
                    eprintln!("event=route_state_read result=failed");
                    continue;
                }
            };
            let candidates = candidate_backends(&state.config, cached.as_ref());
            let result =
                state.discover_once(&hostname, || discover_backend(&hostname, state, candidates));
            if let Err(error) = result {
                eprintln!("Eager TLS discovery rejected {hostname}: {error}");
            }
        }
    }
}

fn reconcile_public_workloads(state: &ProxyState, snapshot: &PublicIngressSnapshot) {
    let assignments = match load_public_registry(state, snapshot) {
        Ok(assignments) => assignments,
        Err(_) => return,
    };

    for (hostname, declaration) in &snapshot.routes {
        let desired = match registered_declared_backend(&assignments, declaration) {
            Ok(backend) => backend,
            Err(_) => {
                deactivate_route(state, hostname, false, "missing_registration");
                set_route_failure(state, hostname, RouteFailure::MissingRegistration);
                continue;
            }
        };
        let active = state
            .routes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(hostname)
            .cloned();
        let active = match active {
            Some(active)
                if active.declaration_generation == Some(snapshot.generation)
                    && active.backend == desired =>
            {
                Some(active)
            }
            Some(_) => {
                deactivate_route(state, hostname, false, "declaration_changed");
                None
            }
            None => None,
        };

        if let Some(active) = active {
            let now_unix_seconds = current_unix_seconds();
            if !active.certificate_is_valid_at(now_unix_seconds) {
                deactivate_expired_route(state, hostname, now_unix_seconds);
                continue;
            }
            if !is_port_open(i64::from(active.backend.port)) {
                record_tcp_failure(state, hostname);
                continue;
            }
            let recovered = active.tcp_failures > 0;
            let tls_due = active.last_tls_check.elapsed() >= TLS_REVALIDATION_INTERVAL;
            if recovered || tls_due {
                revalidate_declared_route(state, snapshot, hostname, &active);
            } else {
                if let Ok(mut routes) = state.routes.write()
                    && let Some(route) = routes.get_mut(hostname)
                {
                    route.tcp_failures = 0;
                }
                clear_route_failure(state, hostname);
            }
            continue;
        }

        let retry_suppressed = match state.negative.lock() {
            Ok(mut negative) => {
                let now = Instant::now();
                negative.retain(|_, expires_at| *expires_at > now);
                negative.contains_key(hostname)
            }
            Err(_) => return,
        };
        if retry_suppressed {
            continue;
        }
        if activate_declared_route(hostname, declaration, snapshot.generation, desired, state)
            .is_err()
        {
            cache_negative(state, hostname);
        }
    }
}

fn revalidate_declared_route(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    hostname: &str,
    route: &ActiveRoute,
) {
    let Some(_permit) = state.probes.acquire(Instant::now() + DISCOVERY_TIMEOUT) else {
        set_route_failure(state, hostname, RouteFailure::CapacityUnavailable);
        return;
    };
    let certificate = match probe_backend(
        hostname,
        &route.backend,
        state.probe_connector_override.as_ref(),
    ) {
        Ok(certificate) => certificate,
        Err(_) => {
            deactivate_route(state, hostname, false, "verification_failed");
            set_route_failure(state, hostname, RouteFailure::VerificationFailed);
            return;
        }
    };
    if install_active_route(
        state,
        hostname,
        ProbeMatch {
            backend: route.backend.clone(),
            certificate,
        },
        Some(snapshot.generation),
    )
    .is_ok()
    {
        clear_route_failure(state, hostname);
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
    if state.public_snapshot().is_some() {
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
        let now_unix_seconds = current_unix_seconds();
        if !route.certificate_is_valid_at(now_unix_seconds) {
            deactivate_expired_route(state, &hostname, now_unix_seconds);
            continue;
        }
        if !registration_matches(&state.config, &route.backend) {
            deactivate_route(state, &hostname, true, "registration_removed");
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
        && let Ok(certificate) = probe_backend(
            hostname,
            &incumbent.backend,
            state.probe_connector_override.as_ref(),
        )
    {
        clear_conflict(state, hostname);
        let _ = install_active_route(
            state,
            hostname,
            ProbeMatch {
                backend: incumbent.backend.clone(),
                certificate,
            },
            None,
        );
        return;
    }

    let Some((route_cache_path, route_cache_storage)) = state.route_cache() else {
        return;
    };
    let cached = match route_cache::load(route_cache_path, hostname, route_cache_storage) {
        Ok(cached) => cached,
        Err(_) => {
            eprintln!("event=route_state_read result=failed");
            return;
        }
    };
    let candidates = candidate_backends(&state.config, cached.as_ref())
        .into_iter()
        .filter(|backend| backend != &incumbent.backend)
        .collect();
    let mut matches = probe_candidates(hostname, candidates, state);

    match matches.len() {
        0 => {
            clear_conflict(state, hostname);
            deactivate_route(state, hostname, false, "verification_failed");
        }
        1 => {
            clear_conflict(state, hostname);
            let replacement = matches.pop().unwrap();
            eprintln!(
                "event=route result=moved hostname={hostname} from_port={} to_port={}",
                incumbent.backend.port, replacement.backend.port
            );
            let _ = install_active_route(state, hostname, replacement, None);
        }
        _ => {
            record_conflict(
                state,
                hostname,
                matches.into_iter().map(|matched| matched.backend).collect(),
            );
            deactivate_route(state, hostname, false, "conflict");
        }
    }
}

fn install_active_route(
    state: &ProxyState,
    hostname: &str,
    matched: ProbeMatch,
    declaration_generation: Option<u64>,
) -> Result<(), String> {
    let now_unix_seconds = current_unix_seconds();
    let expiry_state = matched.certificate.expiry_state_at(now_unix_seconds);
    if expiry_state == CertificateExpiryState::Expired {
        return Err("certificate expired before route activation".to_string());
    }
    let profile = state
        .hosting_profile
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match (declaration_generation, &*profile) {
        (Some(generation), HostingProfile::Public(snapshot))
            if snapshot.generation == generation =>
        {
            let declaration = snapshot.routes.get(hostname).ok_or_else(|| {
                "Route Declaration changed while certificate proof was pending".to_string()
            })?;
            if declaration.hostname != hostname
                || declaration.workload != matched.backend.project
                || declaration.role != matched.backend.role
            {
                return Err(
                    "Route Declaration changed while certificate proof was pending".to_string(),
                );
            }
        }
        (Some(_), HostingProfile::Public(_)) => {
            return Err(
                "ingress config generation changed while certificate proof was pending".to_string(),
            );
        }
        (Some(_), HostingProfile::Development) => {
            return Err("public Route Declaration is no longer active".to_string());
        }
        (None, HostingProfile::Public(_)) => {
            return Err("dynamic route installation is disabled in public mode".to_string());
        }
        (None, HostingProfile::Development) => {}
    }
    let route_cache = state.route_cache_for_profile(&profile);

    let mut routes = state
        .routes
        .write()
        .map_err(|_| "route table lock poisoned".to_string())?;
    if !routes.contains_key(hostname) && routes.len() >= MAX_VERIFIED_ROUTES {
        let _ = state.route_capacity_rejections.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |count| Some(count.saturating_add(1)),
        );
        return Err(format!(
            "verified route capacity of {MAX_VERIFIED_ROUTES} is exhausted"
        ));
    }
    let previous = routes.get(hostname);
    let same_certificate = previous.is_some_and(|active| {
        active.backend == matched.backend
            && active.certificate.fingerprint == matched.certificate.fingerprint
    });
    let rotated = previous.is_some_and(|active| {
        active.backend == matched.backend
            && active.certificate.fingerprint != matched.certificate.fingerprint
    });
    let previous_warning = if same_certificate {
        previous.and_then(|active| active.last_expiry_warning)
    } else {
        None
    };
    let current_warning = expiry_state.warning_threshold_days().map(|_| expiry_state);
    let warning_to_emit = if declaration_generation.is_some() {
        current_warning
            .filter(|warning| previous_warning.is_none_or(|previous| *warning > previous))
    } else {
        None
    };
    let last_expiry_warning = match (previous_warning, current_warning) {
        (Some(previous), Some(current)) => Some(previous.max(current)),
        (previous, current) => previous.or(current),
    };
    if let Some((route_cache_path, route_cache_storage)) = route_cache {
        route_cache::store(
            route_cache_path,
            route_cache_storage,
            hostname,
            &matched.backend.project,
            &matched.backend.role,
            &matched.certificate.fingerprint,
        )?;
    }
    routes.insert(
        hostname.to_string(),
        ActiveRoute {
            backend: matched.backend.clone(),
            certificate: matched.certificate.clone(),
            last_expiry_warning,
            declaration_generation,
            last_tls_check: Instant::now(),
            tcp_failures: 0,
        },
    );
    drop(routes);
    drop(profile);

    if rotated {
        eprintln!(
            "event=certificate result=rotated hostname={hostname} backend_port={}",
            matched.backend.port
        );
    }
    if let Some(warning) = warning_to_emit {
        eprintln!(
            "event=certificate result=expiry_warning hostname={hostname} threshold_days={} not_after_unix_seconds={}",
            warning
                .warning_threshold_days()
                .expect("only warning states are emitted"),
            matched.certificate.not_after_unix_seconds
        );
    }

    Ok(())
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
        deactivate_route(state, hostname, false, "backend_unavailable");
    }
}

fn deactivate_expired_route(state: &ProxyState, hostname: &str, now_unix_seconds: u64) -> bool {
    let removed = state.routes.write().ok().is_some_and(|mut routes| {
        if routes
            .get(hostname)
            .is_some_and(|route| !route.certificate_is_valid_at(now_unix_seconds))
        {
            routes.remove(hostname);
            true
        } else {
            false
        }
    });
    if removed {
        set_route_failure(state, hostname, RouteFailure::CertificateExpired);
        eprintln!("event=route result=deactivated hostname={hostname} reason=certificate_expired");
    }
    removed
}

fn deactivate_route(state: &ProxyState, hostname: &str, remove_cached: bool, reason: &'static str) {
    let removed = state
        .routes
        .write()
        .ok()
        .and_then(|mut routes| routes.remove(hostname))
        .is_some();
    if removed {
        eprintln!("event=route result=deactivated hostname={hostname} reason={reason}");
    }
    if remove_cached
        && let Some((route_cache_path, route_cache_storage)) = state.route_cache()
        && route_cache::remove(route_cache_path, route_cache_storage, hostname).is_err()
    {
        eprintln!("event=route_state_update result=failed");
    }
}

fn candidate_backends(config: &Path, cached: Option<&route_cache::CachedRoute>) -> Vec<Backend> {
    candidate_backends_before(config, cached, None)
}

fn candidate_backends_until(
    config: &Path,
    cached: Option<&route_cache::CachedRoute>,
    deadline: Instant,
) -> Vec<Backend> {
    candidate_backends_before(config, cached, Some(deadline))
}

fn candidate_backends_before(
    config: &Path,
    cached: Option<&route_cache::CachedRoute>,
    deadline: Option<Instant>,
) -> Vec<Backend> {
    let document = read_config(config);
    let mut candidates = Vec::new();

    if let Some(projects) = document.get("ports").and_then(|value| value.as_table()) {
        'projects: for (project, roles) in projects {
            let Some(roles) = roles.as_table() else {
                continue;
            };
            for role in ["https", "main"] {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    break 'projects;
                }
                let Some(port) = roles
                    .get(role)
                    .and_then(|value| value.as_integer())
                    .and_then(|port| u16::try_from(port).ok())
                else {
                    continue;
                };
                let is_open = if let Some(deadline) = deadline {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        break 'projects;
                    };
                    let address: SocketAddr = ([127, 0, 0, 1], port).into();
                    TcpStream::connect_timeout(&address, remaining.min(Duration::from_millis(100)))
                        .is_ok()
                } else {
                    is_port_open(i64::from(port))
                };
                if !is_open {
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
    probe_candidates_until(
        hostname,
        candidates,
        state,
        Instant::now() + DISCOVERY_TIMEOUT,
    )
}

fn probe_candidates_until(
    hostname: &str,
    candidates: Vec<Backend>,
    state: &ProxyState,
    deadline: Instant,
) -> Vec<ProbeMatch> {
    let (sender, receiver) = mpsc::channel();
    let launch_deadline = deadline.checked_sub(PROBE_TIMEOUT).unwrap_or(deadline);

    for backend in candidates {
        if Instant::now() >= launch_deadline {
            break;
        }
        let sender = sender.clone();
        let hostname = hostname.to_string();
        let probes = Arc::clone(&state.probes);
        let connector = state.probe_connector_override.clone();
        let Some(permit) = probes.acquire(launch_deadline) else {
            break;
        };
        if let Err(error) = thread::Builder::new()
            .name("phx-port-probe".to_string())
            .spawn(move || {
                let _permit = permit;
                match probe_backend_until(&hostname, &backend, connector.as_ref(), deadline) {
                    Ok(certificate) => {
                        let _ = sender.send(ProbeMatch {
                            backend,
                            certificate,
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
                        certificate: matched.certificate.clone(),
                    };
                }
            })
            .or_insert(matched);
    }
    let mut preferred: Vec<_> = by_project.into_values().collect();
    preferred.sort_by(|left, right| left.backend.cmp(&right.backend));
    preferred
}

fn probe_backend(
    hostname: &str,
    backend: &Backend,
    connector_override: Option<&TlsConnector>,
) -> Result<CertificateProof, String> {
    probe_backend_until(
        hostname,
        backend,
        connector_override,
        Instant::now() + PROBE_TIMEOUT,
    )
}

pub(crate) fn verify_declared_route_certificate(
    hostname: &str,
    port: u16,
    connector: &TlsConnector,
) -> Result<(), String> {
    let backend = Backend {
        project: "preflight".to_string(),
        role: "preflight".to_string(),
        port,
    };
    probe_backend(hostname, &backend, Some(connector)).map(|_| ())
}

fn probe_backend_until(
    hostname: &str,
    backend: &Backend,
    connector_override: Option<&TlsConnector>,
    deadline: Instant,
) -> Result<CertificateProof, String> {
    let remaining = route_deadline_remaining(deadline)?;
    let stream = connect_backend_with_timeout(backend, remaining.min(PROBE_TIMEOUT))
        .map_err(|error| format!("TCP connection failed: {error}"))?;
    let system_connector;
    let connector = if let Some(connector) = connector_override {
        connector
    } else {
        system_connector =
            TlsConnector::new().map_err(|error| format!("cannot create TLS connector: {error}"))?;
        &system_connector
    };
    let tls = connector
        .connect(hostname, stream)
        .map_err(|error| format!("TLS validation failed: {error}"))?;
    ensure_before_route_deadline(deadline)?;
    let certificate = tls
        .peer_certificate()
        .map_err(|error| format!("cannot inspect peer certificate: {error}"))?
        .ok_or_else(|| "backend did not present a certificate".to_string())?;
    let der = certificate
        .to_der()
        .map_err(|error| format!("cannot encode peer certificate: {error}"))?;
    let digest = Sha256::digest(&der);
    let (_, certificate) = X509Certificate::from_der(&der)
        .map_err(|error| format!("cannot parse peer certificate: {error}"))?;
    let not_after_unix_seconds = u64::try_from(certificate.validity().not_after.timestamp())
        .map_err(|_| "peer certificate expiry precedes the Unix epoch".to_string())?;
    ensure_before_route_deadline(deadline)?;
    Ok(CertificateProof {
        fingerprint: digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
        not_after_unix_seconds,
    })
}

fn connect_backend_with_timeout(backend: &Backend, timeout: Duration) -> io::Result<TcpStream> {
    let address: SocketAddr = ([127, 0, 0, 1], backend.port).into();
    let stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveRoute, Backend, CONTROL_RESPONSE_LIMIT, CertificateExpiryState, CertificateProof,
        DELIVERY_EVENT_INTERVAL, DeliveryOutcome, IngressShutdown, MAX_PROBES, MAX_ROUTE_CONFLICTS,
        MAX_ROUTE_DIAGNOSTICS, MAX_VERIFIED_ROUTES, MAX_WAITING_CLIENTS, OVERLOAD_EVENT_INTERVAL,
        ProbeLimiter, ProbeMatch, ProxyState, QueuedRouteSelection, RelayJob, RouteSelectionJob,
        SOURCE_DIAGNOSTIC_EVENT_INTERVAL, TLS_REVALIDATION_INTERVAL, TokioIngress, WaitingClient,
        cache_negative, clear_conflict, collect_probe_matches, commit_relay_start,
        current_active_backend, current_unix_seconds, handle_connection, handle_route_selection,
        install_active_route, observe_workloads, prefer_https_per_project,
        reap_ready_connection_tasks, reconcile_routes, reconcile_workloads, record_conflict,
        relay_tokio_connection, relay_tokio_connection_with_connector, reload_public_profile,
        render_control_response, render_prometheus_metrics, resolve_backend, select_tokio_route,
        serve_tokio_ingress, supports_eager_discovery,
    };
    #[cfg(unix)]
    use super::{ControlAccess, ControlEndpointPolicy, ControlPeer, bind_private_control_socket};
    #[cfg(target_os = "linux")]
    use super::{
        HandoffJob, IngressLimits, SystemCapacity, drain_connection_tasks, prepare_handoff,
    };
    use crate::{
        admission::AdmissionRejection,
        ingress_config::{
            DEFAULT_RELAY_IDLE_TIMEOUT, HostingProfile, MAX_ROUTE_DECLARATIONS,
            PublicIngressSnapshot, RouteDeclaration, SourceDiagnosticsConfig,
        },
        observability::PROMETHEUS_BODY_LIMIT,
        production_paths::{IntentOwner, ProductionPaths},
        route_cache, update_config,
    };
    #[cfg(target_os = "linux")]
    use crate::{
        handoff::{self, EndpointIdentity},
        handoff_protocol::{Message, decode, encode},
    };
    use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};
    #[cfg(target_os = "linux")]
    use nix::sys::socket::{
        AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
        accept, bind, listen, recv, recvmsg, send, socket,
    };
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        PKCS_RSA_SHA256,
    };
    use std::collections::BTreeMap;
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::io::IoSliceMut;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    #[cfg(target_os = "linux")]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    #[cfg(unix)]
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, RwLock};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime};
    use tempfile::{TempDir, tempdir_in};
    use tokio::net::TcpStream as TokioTcpStream;
    use tokio::sync::oneshot;
    use tokio::task::JoinSet;
    use toml_edit::value;

    fn tempdir() -> io::Result<TempDir> {
        #[cfg(unix)]
        let root = Path::new("/tmp").canonicalize()?;
        #[cfg(not(unix))]
        let root = std::env::temp_dir().canonicalize()?;
        tempdir_in(root)
    }

    fn running_shutdown() -> IngressShutdown {
        IngressShutdown::new(Duration::from_secs(1))
    }

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
            certificate: CertificateProof {
                fingerprint: "AA:BB".to_string(),
                not_after_unix_seconds: u64::MAX,
            },
            last_expiry_warning: None,
            declaration_generation: None,
            last_tls_check: Instant::now(),
            tcp_failures: 0,
        }
    }

    #[test]
    fn certificate_expiry_state_uses_the_fixed_warning_thresholds() {
        let now = 1_000_000;
        for (remaining, expected) in [
            (31 * 24 * 60 * 60, CertificateExpiryState::Valid),
            (30 * 24 * 60 * 60, CertificateExpiryState::Warning30Days),
            (14 * 24 * 60 * 60, CertificateExpiryState::Warning14Days),
            (7 * 24 * 60 * 60, CertificateExpiryState::Warning7Days),
            (24 * 60 * 60, CertificateExpiryState::Warning1Day),
            (0, CertificateExpiryState::Expired),
        ] {
            assert_eq!(CertificateExpiryState::at(now + remaining, now), expected);
        }
    }

    #[test]
    fn expired_optional_certificate_degrades_without_blocking_readiness() {
        const HOSTNAME: &str = "optional.example.test";
        let mut declaration = match public_profile(HOSTNAME, "optional-web") {
            HostingProfile::Public(snapshot) => snapshot.routes[HOSTNAME].clone(),
            HostingProfile::Development => unreachable!(),
        };
        declaration.required = false;
        let profile = HostingProfile::Public(Arc::new(PublicIngressSnapshot {
            ingress_config: PathBuf::from("ingress.toml"),
            intent_owner: IntentOwner::EffectiveUser,
            generation: 1,
            listeners: None,
            metrics: None,
            source_diagnostics: None,
            routes: BTreeMap::from([(HOSTNAME.to_string(), declaration)]),
        }));
        let directory = tempdir().unwrap();
        let state = ProxyState::new_with_profile(directory.path().join("ports.toml"), profile);
        let mut active = active_route(Backend {
            project: "optional-web".to_string(),
            role: "https".to_string(),
            port: 4401,
        });
        active.declaration_generation = Some(1);
        active.certificate.not_after_unix_seconds = current_unix_seconds();
        state
            .routes
            .write()
            .unwrap()
            .insert(HOSTNAME.to_string(), active);

        let status = serde_json::from_str::<serde_json::Value>(&render_control_response(
            &state,
            &running_shutdown(),
            "STATUS JSON",
        ))
        .unwrap();
        assert_eq!(status["ready"], true);
        assert_eq!(status["active_routes"], 0);
        assert_eq!(status["degraded_route_count"], 1);
        assert_eq!(
            status["degraded_routes"][0]["reason"],
            "certificate_expired"
        );
    }

    #[cfg(unix)]
    #[test]
    fn control_socket_is_private_when_published() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("control.sock");

        let listener =
            bind_private_control_socket(&path, ControlEndpointPolicy::development()).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);

        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop((client, server, listener));
    }

    #[cfg(unix)]
    #[test]
    fn control_authorization_is_peer_authenticated_and_command_aware() {
        let public = ControlEndpointPolicy::public(2000);
        let root = ControlPeer { uid: 0, gid: 0 };
        let service = ControlPeer {
            uid: nix::unistd::geteuid().as_raw(),
            gid: 3000,
        };
        let administrator = ControlPeer {
            uid: u32::MAX - 1,
            gid: 2000,
        };
        let outsider = ControlPeer {
            uid: u32::MAX,
            gid: 3000,
        };

        for peer in [root, service, administrator] {
            assert!(public.authorizes(peer, ControlAccess::ReadOnly));
        }
        assert!(public.authorizes(root, ControlAccess::Mutation));
        assert!(!public.authorizes(service, ControlAccess::Mutation));
        assert!(!public.authorizes(administrator, ControlAccess::Mutation));
        assert!(!public.authorizes(outsider, ControlAccess::ReadOnly));
        assert!(!public.authorizes(outsider, ControlAccess::Mutation));

        let development = ControlEndpointPolicy::development();
        assert!(development.authorizes(service, ControlAccess::ReadOnly));
        assert!(development.authorizes(service, ControlAccess::Mutation));
        assert!(development.authorizes(root, ControlAccess::Mutation));
        assert!(!development.authorizes(outsider, ControlAccess::ReadOnly));
    }

    #[derive(Clone)]
    struct TestCertificate {
        certificate_pem: String,
        private_key_pem: String,
    }

    // Security.framework cannot import rcgen's unencrypted ECDSA PKCS#8 keys.
    const TEST_RSA_PRIVATE_KEY: &str = include_str!("../tests/fixtures/proxy-test-rsa-key.pem");

    impl TestCertificate {
        fn parameters_for_hostnames(hostnames: Vec<String>) -> CertificateParams {
            let mut certificate_params = CertificateParams::new(hostnames).unwrap();
            let now = SystemTime::now();
            certificate_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
            certificate_params.not_after = (now + Duration::from_secs(30 * 24 * 60 * 60)).into();
            certificate_params.is_ca = IsCa::ExplicitNoCa;
            certificate_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            certificate_params
        }

        fn parameters_for_hostname(hostname: &str) -> CertificateParams {
            Self::parameters_for_hostnames(vec![hostname.to_string()])
        }

        fn for_hostname(hostname: &str) -> Self {
            Self::for_hostnames(&[hostname])
        }

        fn for_hostname_valid_for(hostname: &str, valid_for: Duration) -> Self {
            Self::for_hostnames_valid_for(&[hostname], valid_for)
        }

        fn for_hostnames(hostnames: &[&str]) -> Self {
            Self::for_hostnames_valid_for(hostnames, Duration::from_secs(30 * 24 * 60 * 60))
        }

        fn for_hostnames_valid_for(hostnames: &[&str], valid_for: Duration) -> Self {
            let signing_key =
                KeyPair::from_pkcs8_pem_and_sign_algo(TEST_RSA_PRIVATE_KEY, &PKCS_RSA_SHA256)
                    .unwrap();
            let mut certificate_params = Self::parameters_for_hostnames(
                hostnames
                    .iter()
                    .map(|hostname| hostname.to_string())
                    .collect(),
            );
            certificate_params.distinguished_name = DistinguishedName::new();
            certificate_params.distinguished_name.push(
                DnType::CommonName,
                format!("{}-{}", hostnames[0], valid_for.as_secs()),
            );
            certificate_params.not_after = (SystemTime::now() + valid_for).into();
            let cert = certificate_params.self_signed(&signing_key).unwrap();
            Self {
                certificate_pem: cert.pem(),
                private_key_pem: TEST_RSA_PRIVATE_KEY.to_string(),
            }
        }

        fn connector(&self) -> TlsConnector {
            Self::connector_for(&[self])
        }

        fn connector_for(certificates: &[&Self]) -> TlsConnector {
            let mut builder = TlsConnector::builder();
            builder.disable_built_in_roots(true);
            for certificate in certificates {
                builder.add_root_certificate(
                    Certificate::from_pem(certificate.certificate_pem.as_bytes()).unwrap(),
                );
            }
            builder.build().unwrap()
        }

        fn unrelated_connector(hostname: &str) -> TlsConnector {
            let signing_key = KeyPair::generate().unwrap();
            let cert = Self::parameters_for_hostname(hostname)
                .self_signed(&signing_key)
                .unwrap();
            let mut builder = TlsConnector::builder();
            builder.disable_built_in_roots(true);
            builder.add_root_certificate(Certificate::from_pem(cert.pem().as_bytes()).unwrap());
            builder.build().unwrap()
        }
    }

    struct TestTlsBackend {
        address: SocketAddr,
        acceptor: Arc<RwLock<TlsAcceptor>>,
        accepted: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl TestTlsBackend {
        fn start(certificate: &TestCertificate, response: &'static [u8]) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let identity = Identity::from_pkcs8(
                certificate.certificate_pem.as_bytes(),
                certificate.private_key_pem.as_bytes(),
            )
            .unwrap();
            let acceptor = Arc::new(RwLock::new(TlsAcceptor::new(identity).unwrap()));
            let accepted = Arc::new(AtomicUsize::new(0));
            let shutdown = Arc::new(AtomicBool::new(false));
            let acceptor_for_worker = Arc::clone(&acceptor);
            let accepted_for_worker = Arc::clone(&accepted);
            let shutdown_for_worker = Arc::clone(&shutdown);
            let worker = thread::spawn(move || {
                while !shutdown_for_worker.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            accepted_for_worker.fetch_add(1, Ordering::AcqRel);
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let acceptor = acceptor_for_worker.read().unwrap().clone();
                            if let Ok(mut tls) = acceptor.accept(stream) {
                                let mut request = [0_u8; 64];
                                if tls.read(&mut request).is_ok_and(|read| read > 0) {
                                    tls.write_all(response).unwrap();
                                    tls.flush().unwrap();
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("test TLS backend accept failed: {error}"),
                    }
                }
            });
            Self {
                address,
                acceptor,
                accepted,
                shutdown,
                worker: Some(worker),
            }
        }

        fn port(&self) -> u16 {
            self.address.port()
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::Acquire)
        }

        fn replace_certificate(&self, certificate: &TestCertificate) {
            let identity = Identity::from_pkcs8(
                certificate.certificate_pem.as_bytes(),
                certificate.private_key_pem.as_bytes(),
            )
            .unwrap();
            *self.acceptor.write().unwrap() = TlsAcceptor::new(identity).unwrap();
        }
    }

    impl Drop for TestTlsBackend {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    #[cfg(unix)]
    fn write_logical_registry(directory: &Path, assignments: &[(&str, u16)]) -> PathBuf {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = directory.canonicalize().unwrap();
        let registry = directory.join("ports.toml");
        let mut content = String::from("[ports]\n");
        for (workload, port) in assignments {
            content.push_str(&format!("\n[ports.{workload}]\nhttps = {port}\n"));
        }
        fs::write(&registry, content).unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();
        registry
    }

    fn public_profile(hostname: &str, workload: &str) -> HostingProfile {
        let declaration = RouteDeclaration {
            hostname: hostname.to_string(),
            workload: workload.to_string(),
            role: "https".to_string(),
            required: true,
            relay_idle_timeout: Some(DEFAULT_RELAY_IDLE_TIMEOUT),
        };
        HostingProfile::Public(Arc::new(PublicIngressSnapshot {
            ingress_config: PathBuf::from("ingress.toml"),
            intent_owner: IntentOwner::EffectiveUser,
            generation: 1,
            listeners: None,
            metrics: None,
            source_diagnostics: None,
            routes: BTreeMap::from([(hostname.to_string(), declaration)]),
        }))
    }

    #[cfg(unix)]
    #[test]
    fn late_public_workload_activates_only_after_registration_and_certificate_proof() {
        const HOSTNAME: &str = "late.example.test";

        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let registry = directory.path().canonicalize().unwrap().join("ports.toml");
        let certificate = TestCertificate::for_hostname(HOSTNAME);
        let backend = TestTlsBackend::start(&certificate, b"late");
        let state = ProxyState::new_with_profile_and_connector(
            registry.clone(),
            public_profile(HOSTNAME, "late-web"),
            certificate.connector(),
        );

        assert!(state.routes.read().unwrap().is_empty());
        assert_eq!(backend.accepted(), 0);

        write_logical_registry(directory.path(), &[("late-web", backend.port())]);
        reconcile_workloads(&state);

        let routes = state.routes.read().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[HOSTNAME].backend,
            Backend {
                project: "late-web".to_string(),
                role: "https".to_string(),
                port: backend.port(),
            }
        );
        drop(routes);
        let status = serde_json::from_str::<serde_json::Value>(&render_control_response(
            &state,
            &running_shutdown(),
            "STATUS JSON",
        ))
        .unwrap();
        assert_eq!(
            status["certificate_routes"][0]["expiry_state"],
            "warning_30_days"
        );
        assert_eq!(status["ready"], true);
        assert_eq!(backend.accepted(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn declared_certificate_rotation_deactivates_invalid_and_expired_proof() {
        const HOSTNAME: &str = "rotate.example.test";

        let initial = TestCertificate::for_hostname_valid_for(
            HOSTNAME,
            Duration::from_secs(60 * 24 * 60 * 60),
        );
        let rotated = TestCertificate::for_hostname_valid_for(
            HOSTNAME,
            Duration::from_secs(13 * 24 * 60 * 60),
        );
        let invalid = TestCertificate::for_hostname("wrong.example.test");
        let connector = TestCertificate::connector_for(&[&initial, &rotated, &invalid]);
        let backend = TestTlsBackend::start(&initial, b"rotated");
        let directory = tempdir().unwrap();
        let registry = write_logical_registry(directory.path(), &[("rotate-web", backend.port())]);
        let state = ProxyState::new_with_profile_and_connector(
            registry,
            public_profile(HOSTNAME, "rotate-web"),
            connector,
        );

        reconcile_workloads(&state);
        let initial_fingerprint = state.routes.read().unwrap()[HOSTNAME]
            .certificate
            .fingerprint
            .clone();

        backend.replace_certificate(&rotated);
        state
            .routes
            .write()
            .unwrap()
            .get_mut(HOSTNAME)
            .unwrap()
            .last_tls_check = Instant::now() - TLS_REVALIDATION_INTERVAL;
        reconcile_workloads(&state);

        let active = state.routes.read().unwrap()[HOSTNAME].clone();
        assert_ne!(active.certificate.fingerprint, initial_fingerprint);
        assert_eq!(
            active.certificate.expiry_state_at(current_unix_seconds()),
            CertificateExpiryState::Warning14Days
        );
        assert_eq!(
            active.last_expiry_warning,
            Some(CertificateExpiryState::Warning14Days)
        );
        let metrics = render_prometheus_metrics(&state, &running_shutdown());
        assert!(
            metrics.contains(
                "phx_port_route_certificate_not_after_seconds{hostname=\"rotate.example.test\",expiry_state=\"warning_14_days\"}"
            ),
            "{metrics}"
        );

        backend.replace_certificate(&invalid);
        state
            .routes
            .write()
            .unwrap()
            .get_mut(HOSTNAME)
            .unwrap()
            .last_tls_check = Instant::now() - TLS_REVALIDATION_INTERVAL;
        reconcile_workloads(&state);
        assert!(state.routes.read().unwrap().is_empty());
        let invalid_status = serde_json::from_str::<serde_json::Value>(&render_control_response(
            &state,
            &running_shutdown(),
            "STATUS JSON",
        ))
        .unwrap();
        assert_eq!(invalid_status["ready"], false);
        assert_eq!(
            invalid_status["degraded_routes"][0]["reason"],
            "verification_failed"
        );

        backend.replace_certificate(&rotated);
        reconcile_workloads(&state);
        assert_eq!(
            state.routes.read().unwrap()[HOSTNAME]
                .certificate
                .fingerprint,
            active.certificate.fingerprint
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&render_control_response(
                &state,
                &running_shutdown(),
                "STATUS JSON",
            ))
            .unwrap()["ready"],
            true
        );

        state
            .routes
            .write()
            .unwrap()
            .get_mut(HOSTNAME)
            .unwrap()
            .certificate
            .not_after_unix_seconds = current_unix_seconds();
        assert!(current_active_backend(&state, HOSTNAME).unwrap().is_none());
        let expired_status = serde_json::from_str::<serde_json::Value>(&render_control_response(
            &state,
            &running_shutdown(),
            "STATUS JSON",
        ))
        .unwrap();
        assert_eq!(expired_status["ready"], false);
        assert_eq!(
            expired_status["degraded_routes"][0]["reason"],
            "certificate_expired"
        );
    }

    #[cfg(unix)]
    #[test]
    fn multiple_declared_routes_activate_only_their_exact_workloads() {
        const FIRST_HOSTNAME: &str = "api.example.test";
        const SECOND_HOSTNAME: &str = "www.example.test";

        let directory = tempdir().unwrap();
        let certificate = TestCertificate::for_hostnames(&[FIRST_HOSTNAME, SECOND_HOSTNAME]);
        let first_backend = TestTlsBackend::start(&certificate, b"first");
        let second_backend = TestTlsBackend::start(&certificate, b"second");
        let registry = write_logical_registry(
            directory.path(),
            &[
                ("api-web", first_backend.port()),
                ("www-web", second_backend.port()),
            ],
        );
        let routes = [
            (FIRST_HOSTNAME, "api-web", true),
            (SECOND_HOSTNAME, "www-web", false),
        ]
        .into_iter()
        .map(|(hostname, workload, required)| {
            (
                hostname.to_string(),
                RouteDeclaration {
                    hostname: hostname.to_string(),
                    workload: workload.to_string(),
                    role: "https".to_string(),
                    required,
                    relay_idle_timeout: Some(DEFAULT_RELAY_IDLE_TIMEOUT),
                },
            )
        })
        .collect();
        let profile = HostingProfile::Public(Arc::new(PublicIngressSnapshot {
            ingress_config: PathBuf::from("ingress.toml"),
            intent_owner: IntentOwner::EffectiveUser,
            generation: 1,
            listeners: None,
            metrics: None,
            source_diagnostics: None,
            routes,
        }));
        let state =
            ProxyState::new_with_profile_and_connector(registry, profile, certificate.connector());

        reconcile_workloads(&state);

        let active = state.routes.read().unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(active[FIRST_HOSTNAME].backend.project, "api-web");
        assert_eq!(active[FIRST_HOSTNAME].backend.port, first_backend.port());
        assert_eq!(active[SECOND_HOSTNAME].backend.project, "www-web");
        assert_eq!(active[SECOND_HOSTNAME].backend.port, second_backend.port());
        drop(active);
        assert_eq!(first_backend.accepted(), 1);
        assert_eq!(second_backend.accepted(), 1);
        let status = render_control_response(&state, &running_shutdown(), "STATUS");
        assert!(status.contains("active_routes=2"), "{status}");
        assert!(status.contains("ready=true"), "{status}");
        assert!(status.contains("degraded_routes=0"), "{status}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn saturated_async_handoff_falls_back_without_queueing() {
        const PROJECT: &str = "/project";

        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runtime_directory = directory.path().join("runtime");
        fs::create_dir(&runtime_directory).unwrap();
        fs::set_permissions(&runtime_directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(runtime_directory.join("handoff")).unwrap();
        let endpoint = handoff::endpoint_path(
            EndpointIdentity::Development(PROJECT),
            "https",
            Some(&runtime_directory),
        )
        .unwrap();
        let handoff_listener = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        bind(
            handoff_listener.as_raw_fd(),
            &UnixAddr::new(endpoint.as_path()).unwrap(),
        )
        .unwrap();
        listen(&handoff_listener, Backlog::new(1).unwrap()).unwrap();

        let (handshake_started, handshake_observed) = tokio::sync::oneshot::channel();
        let (release_handshake, wait_for_release) = std::sync::mpsc::channel();
        let receiver = thread::spawn(move || {
            let control = accept(handoff_listener.as_raw_fd()).unwrap();
            let control = unsafe { OwnedFd::from_raw_fd(control) };
            let mut packet = [0_u8; crate::handoff_protocol::MAX_PACKET_LENGTH + 1];
            let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty()).unwrap();
            assert_eq!(decode(&packet[..length]).unwrap(), Message::Hello);
            handshake_started.send(()).unwrap();
            wait_for_release.recv().unwrap();
        });

        let limits = IngressLimits {
            handoff_negotiations: 1,
            ..IngressLimits::default()
        }
        .validate(
            SystemCapacity {
                file_descriptors: None,
                tasks: None,
            },
            1,
        )
        .unwrap();
        let state = Arc::new(ProxyState::with_limits(
            directory.path().join("ports.toml"),
            None,
            HostingProfile::Development,
            Some(runtime_directory),
            limits,
            None,
        ));

        let first_frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_peer = TcpStream::connect(first_frontend.local_addr().unwrap()).unwrap();
        let (first_client, first_source) = first_frontend.accept().unwrap();
        let first_admission = state.admission.try_admit(first_source.ip()).unwrap();
        let first_handoff = HandoffJob {
            client: first_client,
            accepted_at: Instant::now(),
            admission: first_admission,
            hostname: "first.example.test".to_string(),
            peeked_length: 0,
            backend: Backend {
                project: PROJECT.to_string(),
                role: "https".to_string(),
                port: 1,
            },
            cached: false,
            relay_idle_timeout: None,
        };

        let second_frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let second_peer = TcpStream::connect(second_frontend.local_addr().unwrap()).unwrap();
        let (second_client, second_source) = second_frontend.accept().unwrap();
        let second_admission = state.admission.try_admit(second_source.ip()).unwrap();
        let second_handoff = HandoffJob {
            client: second_client,
            accepted_at: Instant::now(),
            admission: second_admission,
            hostname: "second.example.test".to_string(),
            peeked_length: 0,
            backend: Backend {
                project: PROJECT.to_string(),
                role: "https".to_string(),
                port: 1,
            },
            cached: false,
            relay_idle_timeout: None,
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let first = tokio::spawn(prepare_handoff(first_handoff, Arc::clone(&state)));
            tokio::time::timeout(Duration::from_secs(1), handshake_observed)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(state.admission.snapshot().handoff.in_use, 1);

            let second = tokio::time::timeout(
                Duration::from_millis(250),
                prepare_handoff(second_handoff, Arc::clone(&state)),
            )
            .await
            .expect("handoff saturation queued a second blocking operation")
            .unwrap()
            .expect("handoff saturation must retain the original socket for relay");
            assert_eq!(state.queued_connections.load(Ordering::Acquire), 0);
            assert_eq!(state.handoff_capacity_skips.load(Ordering::Acquire), 1);
            assert_eq!(state.handoff_attempts.load(Ordering::Acquire), 1);

            release_handshake.send(()).unwrap();
            let first = first
                .await
                .unwrap()
                .unwrap()
                .expect("pre-delivery handshake failure must retain the socket for relay");
            drop(first);
            drop(second);
        });

        receiver.join().unwrap();
        drop(first_peer);
        drop(second_peer);
        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.handoff.in_use, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_waits_for_phxp_ownership_and_handoff_survives() {
        const PROJECT: &str = "/shutdown-handoff";

        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runtime_directory = directory.path().join("runtime");
        fs::create_dir(&runtime_directory).unwrap();
        fs::set_permissions(&runtime_directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(runtime_directory.join("handoff")).unwrap();
        let endpoint = handoff::endpoint_path(
            EndpointIdentity::Development(PROJECT),
            "https",
            Some(&runtime_directory),
        )
        .unwrap();
        let handoff_listener = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        bind(
            handoff_listener.as_raw_fd(),
            &UnixAddr::new(endpoint.as_path()).unwrap(),
        )
        .unwrap();
        listen(&handoff_listener, Backlog::new(1).unwrap()).unwrap();

        let (descriptor_delivered, descriptor_observed) = tokio::sync::oneshot::channel();
        let (acknowledge, wait_for_acknowledgement) = std::sync::mpsc::channel();
        let receiver = thread::spawn(move || {
            let control = accept(handoff_listener.as_raw_fd()).unwrap();
            let control = unsafe { OwnedFd::from_raw_fd(control) };
            let mut packet = [0_u8; crate::handoff_protocol::MAX_PACKET_LENGTH + 1];
            let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty()).unwrap();
            assert_eq!(decode(&packet[..length]).unwrap(), Message::Hello);
            send(
                control.as_raw_fd(),
                &encode(&Message::Ready).unwrap(),
                MsgFlags::empty(),
            )
            .unwrap();

            let (packet_length, mut descriptors) = {
                let mut ancillary = nix::cmsg_space!([i32; 2]);
                let mut iov = [IoSliceMut::new(&mut packet)];
                let message = recvmsg::<UnixAddr>(
                    control.as_raw_fd(),
                    &mut iov,
                    Some(&mut ancillary),
                    MsgFlags::MSG_CMSG_CLOEXEC,
                )
                .unwrap();
                let descriptors = message
                    .cmsgs()
                    .unwrap()
                    .flat_map(|message| match message {
                        ControlMessageOwned::ScmRights(descriptors) => descriptors,
                        _ => Vec::new(),
                    })
                    .map(|descriptor| unsafe { OwnedFd::from_raw_fd(descriptor) })
                    .collect::<Vec<_>>();
                (message.bytes, descriptors)
            };
            assert_eq!(descriptors.len(), 1);
            let connection_id = match decode(&packet[..packet_length]).unwrap() {
                Message::Handoff(request) => request.connection_id,
                request => panic!("unexpected PHXP request: {request:?}"),
            };
            descriptor_delivered.send(()).unwrap();
            wait_for_acknowledgement.recv().unwrap();
            send(
                control.as_raw_fd(),
                &encode(&Message::Adopted { connection_id }).unwrap(),
                MsgFlags::empty(),
            )
            .unwrap();
            TcpStream::from(descriptors.pop().unwrap())
        });

        let state = Arc::new(ProxyState::new_with_profile_connector_and_runtime(
            directory.path().join("ports.toml"),
            HostingProfile::Development,
            TestCertificate::for_hostname("unused.example.test").connector(),
            runtime_directory,
        ));
        let frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut public_peer = TcpStream::connect(frontend.local_addr().unwrap()).unwrap();
        let (accepted, peer) = frontend.accept().unwrap();
        let handoff = HandoffJob {
            client: accepted,
            accepted_at: Instant::now(),
            admission: state.admission.try_admit(peer.ip()).unwrap(),
            hostname: "shutdown-handoff.example.test".to_string(),
            peeked_length: 0,
            backend: Backend {
                project: PROJECT.to_string(),
                role: "https".to_string(),
                port: 1,
            },
            cached: false,
            relay_idle_timeout: None,
        };
        let shutdown = IngressShutdown::new(Duration::from_secs(1));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let handoff_state = Arc::clone(&state);
            let mut connections = JoinSet::new();
            connections.spawn(async move {
                let outcome = prepare_handoff(handoff, handoff_state).await?;
                if outcome.is_some() {
                    return Err("PHXP handoff unexpectedly retained the relay socket".to_string());
                }
                Ok(())
            });
            tokio::time::timeout(Duration::from_secs(1), descriptor_observed)
                .await
                .unwrap()
                .unwrap();
            shutdown.request();

            let mut failure = None;
            let forced = {
                let drain = drain_connection_tasks(
                    &mut connections,
                    &state,
                    &mut failure,
                    shutdown.drain_deadline(),
                );
                tokio::pin!(drain);
                tokio::select! {
                    forced = &mut drain => {
                        panic!("shutdown cancelled PHXP before ownership resolved: {forced}");
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                acknowledge.send(()).unwrap();
                drain.await
            };
            assert_eq!(forced, 0);
            assert!(failure.is_none());
        });

        let mut handed_off = receiver.join().unwrap();
        public_peer.write_all(b"request").unwrap();
        let mut request = [0_u8; 7];
        handed_off.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"request");
        handed_off.write_all(b"response").unwrap();
        let mut response = [0_u8; 8];
        public_peer.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"response");

        assert_eq!(state.successful_handoffs.load(Ordering::Relaxed), 1);
        assert_eq!(state.relayed_connections.load(Ordering::Relaxed), 0);
        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.handoff.in_use, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_route_hands_the_original_descriptor_to_its_logical_workload_endpoint() {
        const HOSTNAME: &str = "handoff.example.test";
        const WORKLOAD: &str = "handoff-web";

        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = directory.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(runtime.join("handoff")).unwrap();
        let endpoint = handoff::endpoint_path(
            EndpointIdentity::Production(WORKLOAD),
            "https",
            Some(&runtime),
        )
        .unwrap();
        let handoff_listener = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        bind(
            handoff_listener.as_raw_fd(),
            &UnixAddr::new(endpoint.as_path()).unwrap(),
        )
        .unwrap();
        listen(&handoff_listener, Backlog::new(1).unwrap()).unwrap();

        let certificate = TestCertificate::for_hostname(HOSTNAME);
        let ordinary_backend = TestTlsBackend::start(&certificate, b"relay");
        let registry =
            write_logical_registry(directory.path(), &[(WORKLOAD, ordinary_backend.port())]);
        let state = Arc::new(ProxyState::new_with_profile_connector_and_runtime(
            registry,
            public_profile(HOSTNAME, WORKLOAD),
            certificate.connector(),
            runtime,
        ));
        reconcile_workloads(&state);
        assert_eq!(ordinary_backend.accepted(), 1);

        let identity = Identity::from_pkcs8(
            certificate.certificate_pem.as_bytes(),
            certificate.private_key_pem.as_bytes(),
        )
        .unwrap();
        let tls_acceptor = TlsAcceptor::new(identity).unwrap();
        let frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let frontend_address = frontend.local_addr().unwrap();
        let receiver = thread::spawn(move || {
            let control = accept(handoff_listener.as_raw_fd()).unwrap();
            let control = unsafe { OwnedFd::from_raw_fd(control) };
            let mut packet = [0_u8; crate::handoff_protocol::MAX_PACKET_LENGTH + 1];

            let length = recv(control.as_raw_fd(), &mut packet, MsgFlags::empty()).unwrap();
            assert_eq!(decode(&packet[..length]).unwrap(), Message::Hello);
            send(
                control.as_raw_fd(),
                &encode(&Message::Ready).unwrap(),
                MsgFlags::empty(),
            )
            .unwrap();

            let (packet_length, descriptors) = {
                let mut ancillary = nix::cmsg_space!([i32; 2]);
                let mut iov = [IoSliceMut::new(&mut packet)];
                let message = recvmsg::<UnixAddr>(
                    control.as_raw_fd(),
                    &mut iov,
                    Some(&mut ancillary),
                    MsgFlags::MSG_CMSG_CLOEXEC,
                )
                .unwrap();
                let descriptors = message
                    .cmsgs()
                    .unwrap()
                    .flat_map(|message| match message {
                        ControlMessageOwned::ScmRights(descriptors) => descriptors,
                        _ => Vec::new(),
                    })
                    .map(|descriptor| unsafe { OwnedFd::from_raw_fd(descriptor) })
                    .collect::<Vec<_>>();
                (message.bytes, descriptors)
            };
            assert_eq!(descriptors.len(), 1);
            let request = decode(&packet[..packet_length]).unwrap();
            let connection_id = match request {
                Message::Handoff(request) if request.requested_sni == HOSTNAME => {
                    request.connection_id
                }
                request => panic!("unexpected PHXP request: {request:?}"),
            };
            let handed_off = TcpStream::from(descriptors.into_iter().next().unwrap());
            assert_eq!(handed_off.local_addr().unwrap(), frontend_address);
            send(
                control.as_raw_fd(),
                &encode(&Message::Adopted { connection_id }).unwrap(),
                MsgFlags::empty(),
            )
            .unwrap();

            let mut tls = tls_acceptor.accept(handed_off).unwrap();
            let mut request = [0_u8; 7];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"request");
            tls.write_all(b"handoff").unwrap();
            tls.flush().unwrap();
        });

        let client_connector = certificate.connector();
        let client = thread::spawn(move || {
            let stream = TcpStream::connect(frontend_address).unwrap();
            let mut tls = client_connector.connect(HOSTNAME, stream).unwrap();
            tls.write_all(b"request").unwrap();
            let mut response = [0_u8; 7];
            tls.read_exact(&mut response).unwrap();
            response
        });
        let (accepted, peer) = frontend.accept().unwrap();
        let admission = state.admission.try_admit(peer.ip()).unwrap();
        handle_connection(
            accepted,
            peer.ip(),
            Instant::now(),
            Arc::clone(&state),
            admission,
        )
        .unwrap();

        assert_eq!(&client.join().unwrap(), b"handoff");
        receiver.join().unwrap();
        assert_eq!(ordinary_backend.accepted(), 1);
        assert_eq!(state.handoff_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(state.successful_handoffs.load(Ordering::Relaxed), 1);
        assert_eq!(state.handoff_fallbacks.load(Ordering::Relaxed), 0);
        assert_eq!(state.relayed_connections.load(Ordering::Relaxed), 0);
        assert!(endpoint.exists());
    }

    #[cfg(unix)]
    #[test]
    fn public_route_requires_exact_declaration_and_certificate_before_relay() {
        const HOSTNAME: &str = "declared.example.test";

        let directory = tempdir().unwrap();
        let valid_certificate = TestCertificate::for_hostname(HOSTNAME);
        let declared_backend = TestTlsBackend::start(&valid_certificate, b"declared");
        let decoy_backend = TestTlsBackend::start(&valid_certificate, b"decoy");
        let registry = write_logical_registry(
            directory.path(),
            &[
                ("contoso-web", declared_backend.port()),
                ("decoy-web", decoy_backend.port()),
            ],
        );
        let state = Arc::new(ProxyState::new_with_profile_connector_and_runtime(
            registry.clone(),
            public_profile(HOSTNAME, "contoso-web"),
            valid_certificate.connector(),
            directory.path().join("missing-handoff-runtime"),
        ));

        let frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let frontend_address = frontend.local_addr().unwrap();
        let client_connector = valid_certificate.connector();
        let client = thread::spawn(move || {
            let stream = TcpStream::connect(frontend_address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls = client_connector.connect(HOSTNAME, stream).unwrap();
            tls.write_all(b"request").unwrap();
            let mut response = [0_u8; 8];
            tls.read_exact(&mut response).unwrap();
            response
        });
        let (accepted, peer) = frontend.accept().unwrap();
        let admission = state.admission.try_admit(peer.ip()).unwrap();
        handle_connection(
            accepted,
            peer.ip(),
            Instant::now(),
            Arc::clone(&state),
            admission,
        )
        .unwrap();
        assert_eq!(&client.join().unwrap(), b"declared");
        assert_eq!(declared_backend.accepted(), 2);
        assert_eq!(decoy_backend.accepted(), 0);
        assert_eq!(state.undeclared_registrations.load(Ordering::Acquire), 1);
        let active_routes = state.routes.read().unwrap();
        assert_eq!(active_routes.len(), 1);
        assert_eq!(
            active_routes[HOSTNAME].backend,
            Backend {
                project: "contoso-web".to_string(),
                role: "https".to_string(),
                port: declared_backend.port(),
            }
        );
        drop(active_routes);
        assert!(
            !fs::read_to_string(&registry)
                .unwrap()
                .contains("discovered_routes")
        );
        assert_eq!(state.relayed_connections.load(Ordering::Relaxed), 1);
        assert_eq!(state.handoff_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(state.successful_handoffs.load(Ordering::Relaxed), 0);
        assert_eq!(state.handoff_fallbacks.load(Ordering::Relaxed), 1);
        assert!(state.relay_client_to_workload_bytes.load(Ordering::Relaxed) > 0);
        assert!(state.relay_workload_to_client_bytes.load(Ordering::Relaxed) > 0);
        assert!(state.relay_duration_nanoseconds.load(Ordering::Relaxed) > 0);
        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.relay.in_use, 0);
        let metrics = render_prometheus_metrics(&state, &running_shutdown());
        assert!(metrics.contains("phx_port_relay_bytes_total{direction=\"client_to_workload\"} "));
        assert!(metrics.contains("phx_port_relay_bytes_total{direction=\"workload_to_client\"} "));
        assert!(metrics.contains("phx_port_relay_duration_seconds_total "));
        let status = render_control_response(&state, &running_shutdown(), "STATUS");
        assert!(status.contains("ready=true"), "{status}");
        assert!(status.contains("degraded_routes=0"), "{status}");
        assert!(status.contains("undeclared_registrations=1"), "{status}");

        let undeclared_frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let undeclared_address = undeclared_frontend.local_addr().unwrap();
        let undeclared_connector = valid_certificate.connector();
        let undeclared_client = thread::spawn(move || {
            let stream = TcpStream::connect(undeclared_address).unwrap();
            undeclared_connector.connect("undeclared.example.test", stream)
        });
        let (undeclared, peer) = undeclared_frontend.accept().unwrap();
        let admission = state.admission.try_admit(peer.ip()).unwrap();
        let error = handle_connection(
            undeclared,
            peer.ip(),
            Instant::now(),
            Arc::clone(&state),
            admission,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "public ingress has no Route Declaration for undeclared.example.test"
        );
        assert!(undeclared_client.join().unwrap().is_err());
        assert_eq!(declared_backend.accepted(), 2);
        assert_eq!(decoy_backend.accepted(), 0);

        let invalid_directory = tempdir().unwrap();
        let wrong_hostname_certificate =
            TestCertificate::for_hostname("wrong-hostname.example.test");
        let invalid_backend = TestTlsBackend::start(&wrong_hostname_certificate, b"invalid");
        let invalid_registry = write_logical_registry(
            invalid_directory.path(),
            &[("contoso-web", invalid_backend.port())],
        );
        let invalid_state = ProxyState::new_with_profile_and_connector(
            invalid_registry,
            public_profile(HOSTNAME, "contoso-web"),
            wrong_hostname_certificate.connector(),
        );

        let error = resolve_backend(HOSTNAME, &invalid_state).unwrap_err();
        assert!(error.contains("TLS validation failed"), "{error}");
        assert_eq!(invalid_backend.accepted(), 1);
        assert!(invalid_state.routes.read().unwrap().is_empty());

        let untrusted_directory = tempdir().unwrap();
        let untrusted_certificate = TestCertificate::for_hostname(HOSTNAME);
        let untrusted_backend = TestTlsBackend::start(&untrusted_certificate, b"untrusted");
        let untrusted_registry = write_logical_registry(
            untrusted_directory.path(),
            &[("contoso-web", untrusted_backend.port())],
        );
        let untrusted_state = ProxyState::new_with_profile_and_connector(
            untrusted_registry,
            public_profile(HOSTNAME, "contoso-web"),
            TestCertificate::unrelated_connector(HOSTNAME),
        );

        let error = resolve_backend(HOSTNAME, &untrusted_state).unwrap_err();
        assert!(error.contains("TLS validation failed"), "{error}");
        assert_eq!(untrusted_backend.accepted(), 1);
        assert!(untrusted_state.routes.read().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn shared_registry_port_conflict_never_probes_or_activates_a_declared_route() {
        const HOSTNAME: &str = "declared.example.test";

        let directory = tempdir().unwrap();
        let certificate = TestCertificate::for_hostname(HOSTNAME);
        let backend = TestTlsBackend::start(&certificate, b"never");
        let registry = write_logical_registry(
            directory.path(),
            &[
                ("declared-web", backend.port()),
                ("conflicting-web", backend.port()),
            ],
        );
        let state = ProxyState::new_with_profile_and_connector(
            registry,
            public_profile(HOSTNAME, "declared-web"),
            certificate.connector(),
        );

        reconcile_workloads(&state);

        assert_eq!(backend.accepted(), 0);
        assert!(state.routes.read().unwrap().is_empty());
        assert!(!state.registry_valid.load(Ordering::Acquire));
        assert_eq!(state.rejected_registry_snapshots.load(Ordering::Acquire), 1);
        let routes = render_control_response(&state, &running_shutdown(), "ROUTES");
        assert!(routes.contains("required\tregistry_invalid"), "{routes}");
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
    fn async_route_selection_queue_is_bounded_and_deadlined() {
        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let shutdown = IngressShutdown::new(Duration::from_secs(1));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();

        let (route_sender, _route_receiver) = std::sync::mpsc::sync_channel(0);
        let ingress = TokioIngress {
            state: Arc::clone(&state),
            shutdown: shutdown.clone(),
            route_sender,
        };
        let error = runtime
            .block_on(select_tokio_route("queued.example.test", &ingress))
            .unwrap_err();
        assert_eq!(error, "route-selection queue capacity exhausted");
        assert_eq!(state.rejected_routing_queue.load(Ordering::Relaxed), 1);
        assert_eq!(state.queued_route_selections.load(Ordering::Relaxed), 0);

        let (route_sender, route_receiver) = std::sync::mpsc::sync_channel(1);
        let ingress = TokioIngress {
            state: Arc::clone(&state),
            shutdown,
            route_sender,
        };
        let error = runtime
            .block_on(select_tokio_route("timeout.example.test", &ingress))
            .unwrap_err();
        assert_eq!(error, "route selection timed out");
        assert_eq!(state.rejected_routing_timeout.load(Ordering::Relaxed), 1);
        assert_eq!(state.queued_route_selections.load(Ordering::Relaxed), 1);
        drop(route_receiver);
        assert_eq!(state.queued_route_selections.load(Ordering::Relaxed), 0);
    }

    #[cfg(unix)]
    #[test]
    fn route_worker_cannot_outlive_its_original_deadline() {
        const HOSTNAME: &str = "deadline.example.test";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_sender, accepted_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            accepted_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            drop(stream);
        });

        let directory = tempdir().unwrap();
        let certificate = TestCertificate::for_hostname(HOSTNAME);
        let registry = write_logical_registry(directory.path(), &[("deadline-web", port)]);
        let state = Arc::new(ProxyState::new_with_profile_and_connector(
            registry,
            public_profile(HOSTNAME, "deadline-web"),
            certificate.connector(),
        ));
        let (result, mut receiver) = tokio::sync::oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(100);
        let job = RouteSelectionJob {
            hostname: HOSTNAME.to_string(),
            deadline,
            result,
            queued: QueuedRouteSelection::new(Arc::clone(&state.queued_route_selections)),
        };
        let route_state = Arc::clone(&state);
        let started = Instant::now();
        let worker = thread::spawn(move || handle_route_selection(job, &route_state));

        accepted_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "stalled certificate probe held a route coordinator past its deadline"
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
        assert_eq!(state.queued_route_selections.load(Ordering::Relaxed), 0);
        assert!(state.routes.read().unwrap().is_empty());

        release_sender.send(()).unwrap();
        server.join().unwrap();
        let permit_deadline = Instant::now() + Duration::from_secs(1);
        while *state.probes.in_use.lock().unwrap() != 0 {
            assert!(
                Instant::now() < permit_deadline,
                "timed-out certificate probe did not release its bounded permit"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn completed_connection_tasks_are_reaped_in_one_bounded_pass() {
        const COMPLETED_TASKS: usize = 256;

        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut connections = JoinSet::new();
            for _ in 0..COMPLETED_TASKS {
                connections.spawn(async { Err("malformed ClientHello".to_string()) });
            }
            tokio::time::sleep(Duration::from_millis(10)).await;

            let mut failure = None;
            assert_eq!(
                reap_ready_connection_tasks(&mut connections, &state, &mut failure),
                COMPLETED_TASKS
            );
            assert!(connections.is_empty());
            assert!(failure.is_none());
            assert_eq!(
                state.rejected_connections.load(Ordering::Relaxed),
                COMPLETED_TASKS as u64
            );
        });
    }

    #[test]
    fn shutdown_cancels_pre_routing_without_leaking_admission() {
        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = IngressShutdown::new(Duration::from_secs(1));
        let ingress_state = Arc::clone(&state);
        let ingress_shutdown = shutdown.clone();
        let (route_sender, _route_receiver) = std::sync::mpsc::sync_channel(1);
        let ingress = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(serve_tokio_ingress(
                vec![listener],
                ingress_state,
                ingress_shutdown,
                route_sender,
            ))
        });

        let mut client = TcpStream::connect(address).unwrap();
        let admission_deadline = Instant::now() + Duration::from_secs(1);
        while state.admission.snapshot().pre_routing.in_use == 0 {
            assert!(
                Instant::now() < admission_deadline,
                "idle ClientHello was never admitted"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let shutdown_started = Instant::now();
        shutdown.request();
        let ingress_report = ingress.join().unwrap();
        assert!(ingress_report.failure.is_none());
        assert_eq!(ingress_report.forced_connections, 0);
        assert!(
            shutdown_started.elapsed() < Duration::from_millis(500),
            "pre-routing cancellation waited for the drain deadline"
        );
        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.relay.in_use, 0);

        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        match client.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                ) => {}
            result => panic!("cancelled pre-routing socket remained open: {result:?}"),
        }
    }

    #[test]
    fn shutdown_wakes_idle_listener_without_timer_progress() {
        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let shutdown = IngressShutdown::new(Duration::from_secs(1));
        let ingress_shutdown = shutdown.clone();
        let (route_sender, _route_receiver) = std::sync::mpsc::sync_channel(1);
        let (report_sender, report_receiver) = std::sync::mpsc::channel();
        let ingress = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            let report = runtime.block_on(serve_tokio_ingress(
                vec![listener],
                state,
                ingress_shutdown,
                route_sender,
            ));
            report_sender.send(report).unwrap();
        });
        let waiter_deadline = Instant::now() + Duration::from_millis(500);
        while shutdown.waiter_count() < 2 {
            assert!(
                Instant::now() < waiter_deadline,
                "listener orchestration never subscribed to direct shutdown notification"
            );
            thread::sleep(Duration::from_millis(5));
        }

        shutdown.request();
        let report = report_receiver
            .recv_timeout(Duration::from_millis(500))
            .expect("shutdown depended on periodic Tokio timer progress");
        assert!(report.failure.is_none());
        assert_eq!(report.forced_connections, 0);
        ingress.join().unwrap();
    }

    #[test]
    fn shutdown_drains_established_relay_until_shared_deadline() {
        const HOSTNAME: &str = "shutdown-relay.example.test";

        let certificate = TestCertificate::for_hostname(HOSTNAME);
        let identity = Identity::from_pkcs8(
            certificate.certificate_pem.as_bytes(),
            certificate.private_key_pem.as_bytes(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::new(identity).unwrap();
        let workload_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let workload_port = workload_listener.local_addr().unwrap().port();
        let workload = thread::spawn(move || {
            let (stream, _) = workload_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut tls = acceptor.accept(stream).unwrap();
            let mut byte = [0_u8; 1];
            while tls.read_exact(&mut byte).is_ok() {
                tls.write_all(&byte).unwrap();
                tls.flush().unwrap();
            }
        });

        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new_with_profile_connector_and_runtime(
            directory.path().join("ports.toml"),
            HostingProfile::Development,
            certificate.connector(),
            directory.path().join("missing-runtime"),
        ));
        state.routes.write().unwrap().insert(
            HOSTNAME.to_string(),
            active_route(Backend {
                project: directory.path().display().to_string(),
                role: "https".to_string(),
                port: workload_port,
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = IngressShutdown::new(Duration::from_millis(250));
        let ingress_state = Arc::clone(&state);
        let ingress_shutdown = shutdown.clone();
        let (route_sender, _route_receiver) = std::sync::mpsc::sync_channel(1);
        let ingress = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(serve_tokio_ingress(
                vec![listener],
                ingress_state,
                ingress_shutdown,
                route_sender,
            ))
        });

        let stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut client = certificate.connector().connect(HOSTNAME, stream).unwrap();
        client.write_all(b"a").unwrap();
        client.flush().unwrap();
        let mut echoed = [0_u8; 1];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"a");

        let relay_deadline = Instant::now() + Duration::from_secs(1);
        while state.admission.snapshot().relay.in_use == 0 {
            assert!(
                Instant::now() < relay_deadline,
                "connection never entered relay ownership"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let shutdown_started = Instant::now();
        shutdown.request();
        thread::sleep(Duration::from_millis(50));
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err(),
            "shutdown retained the process listener copy during relay drain"
        );
        let draining_status = render_control_response(&state, &shutdown, "STATUS");
        assert!(draining_status.starts_with("draining\n"));
        assert!(draining_status.contains("active_relays=1"));
        assert!(draining_status.contains("ready=false"));
        let draining_metrics = render_prometheus_metrics(&state, &shutdown);
        assert!(draining_metrics.contains("phx_port_draining 1"));
        assert!(draining_metrics.contains("phx_port_admission_in_use{stage=\"relay\"} 1"));
        let after_shutdown = (|| -> io::Result<[u8; 1]> {
            client.write_all(b"b")?;
            client.flush()?;
            let mut echoed = [0_u8; 1];
            client.read_exact(&mut echoed)?;
            Ok(echoed)
        })();

        let ingress_report = ingress.join().unwrap();
        let drain_elapsed = shutdown_started.elapsed();
        drop(client);
        workload.join().unwrap();
        assert_eq!(
            after_shutdown.unwrap(),
            *b"b",
            "shutdown closed an established relay instead of draining it"
        );
        assert!(ingress_report.failure.is_none());
        assert_eq!(ingress_report.forced_connections, 1);
        assert!(
            drain_elapsed >= Duration::from_millis(200) && drain_elapsed < Duration::from_secs(1),
            "relay drain lasted {drain_elapsed:?} instead of respecting the shared deadline"
        );
        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.relay.in_use, 0);
    }

    #[test]
    fn async_backend_connect_failure_releases_relay_capacity() {
        let frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let public_peer = TcpStream::connect(frontend.local_addr().unwrap()).unwrap();
        let (accepted, peer) = frontend.accept().unwrap();
        let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable_port = unavailable.local_addr().unwrap().port();
        drop(unavailable);

        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let admission = state.admission.try_admit(peer.ip()).unwrap();
        let job = RelayJob {
            client: accepted,
            admission,
            hostname: "unavailable.example.test".to_string(),
            backend: Backend {
                project: "/unavailable".to_string(),
                role: "https".to_string(),
                port: unavailable_port,
            },
            cached: false,
            idle_timeout: None,
        };
        let (route_sender, _route_receiver) = std::sync::mpsc::sync_channel(1);
        let ingress = TokioIngress {
            state: Arc::clone(&state),
            shutdown: IngressShutdown::new(Duration::from_secs(1)),
            route_sender,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        let error = runtime
            .block_on(relay_tokio_connection(job, &ingress))
            .unwrap_err();
        assert!(error.contains("verified backend disappeared"), "{error}");
        assert_eq!(
            state.relay_backend_connect_failures.load(Ordering::Relaxed),
            1
        );
        assert_eq!(state.relayed_connections.load(Ordering::Relaxed), 0);
        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.relay.in_use, 0);
        drop(public_peer);
    }

    #[test]
    fn shutdown_cancels_pending_relay_establishment_before_start() {
        let frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut public_peer = TcpStream::connect(frontend.local_addr().unwrap()).unwrap();
        let (accepted, peer) = frontend.accept().unwrap();

        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let admission = state.admission.try_admit(peer.ip()).unwrap();
        let job = RelayJob {
            client: accepted,
            admission,
            hostname: "pending.example.test".to_string(),
            backend: Backend {
                project: "/pending".to_string(),
                role: "https".to_string(),
                port: 443,
            },
            cached: false,
            idle_timeout: None,
        };
        let (route_sender, _route_receiver) = std::sync::mpsc::sync_channel(1);
        let ingress = TokioIngress {
            state: Arc::clone(&state),
            shutdown: IngressShutdown::new(Duration::from_secs(1)),
            route_sender,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let (connect_started, connect_started_rx) = oneshot::channel();
            let mut connect_started = Some(connect_started);
            let task_ingress = ingress.clone();
            let relay = tokio::spawn(async move {
                relay_tokio_connection_with_connector(job, &task_ingress, move |_| {
                    if let Some(started) = connect_started.take() {
                        let _ = started.send(());
                    }
                    std::future::pending::<io::Result<TokioTcpStream>>()
                })
                .await
            });
            tokio::time::timeout(Duration::from_secs(1), connect_started_rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(state.admission.snapshot().relay.in_use, 1);

            ingress.shutdown.request();
            tokio::time::timeout(Duration::from_secs(1), relay)
                .await
                .expect("pending relay establishment ignored shutdown")
                .unwrap()
                .unwrap();
        });

        assert_eq!(state.relayed_connections.load(Ordering::Relaxed), 0);
        assert!(
            state.delivery_events.lock().unwrap().windows[DeliveryOutcome::RelayStarted.index()]
                .last_emitted
                .is_none(),
            "cancelled establishment recorded RelayStarted"
        );
        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.relay.in_use, 0);
        public_peer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(
            public_peer.read(&mut byte).unwrap(),
            0,
            "cancelled establishment retained the accepted socket"
        );
    }

    #[test]
    fn relay_start_commit_is_atomic_with_shutdown_request() {
        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let shutdown = IngressShutdown::new(Duration::from_secs(1));
        let (commit_entered, commit_entered_rx) = std::sync::mpsc::channel();
        let (release_commit, release_commit_rx) = std::sync::mpsc::channel();
        let state_for_commit = Arc::clone(&state);
        let shutdown_for_commit = shutdown.clone();
        let commit = thread::spawn(move || {
            shutdown_for_commit.commit_if_running(|| {
                commit_entered.send(()).unwrap();
                release_commit_rx.recv().unwrap();
                state_for_commit
                    .relayed_connections
                    .fetch_add(1, Ordering::Relaxed);
                state_for_commit.record_delivery_outcome(DeliveryOutcome::RelayStarted);
            })
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let shutdown_for_request = shutdown.clone();
        let (request_complete, request_complete_rx) = std::sync::mpsc::channel();
        let request = thread::spawn(move || {
            shutdown_for_request.request();
            request_complete.send(()).unwrap();
        });
        assert!(
            request_complete_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "shutdown published while a relay-start commit held the transition gate"
        );
        release_commit.send(()).unwrap();
        assert!(commit.join().unwrap());
        request_complete_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        request.join().unwrap();

        assert!(shutdown.is_requested());
        assert_eq!(state.relayed_connections.load(Ordering::Relaxed), 1);
        assert!(
            !commit_relay_start(&state, &shutdown),
            "relay start committed after shutdown won the transition gate"
        );
        assert_eq!(state.relayed_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cancelling_async_relay_releases_sockets_and_permits() {
        let frontend = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut public_peer = TcpStream::connect(frontend.local_addr().unwrap()).unwrap();
        let (accepted, peer) = frontend.accept().unwrap();
        let workload = TcpListener::bind("127.0.0.1:0").unwrap();

        let directory = tempdir().unwrap();
        let state = Arc::new(ProxyState::new(directory.path().join("ports.toml")));
        let admission = state.admission.try_admit(peer.ip()).unwrap();
        let job = RelayJob {
            client: accepted,
            admission,
            hostname: "cancelled.example.test".to_string(),
            backend: Backend {
                project: "/cancelled".to_string(),
                role: "https".to_string(),
                port: workload.local_addr().unwrap().port(),
            },
            cached: false,
            idle_timeout: None,
        };
        let (route_sender, _route_receiver) = std::sync::mpsc::sync_channel(1);
        let ingress = TokioIngress {
            state: Arc::clone(&state),
            shutdown: IngressShutdown::new(Duration::from_secs(1)),
            route_sender,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let relay = tokio::spawn(async move { relay_tokio_connection(job, &ingress).await });
            tokio::time::timeout(Duration::from_secs(1), async {
                while state.relayed_connections.load(Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(state.admission.snapshot().relay.in_use, 1);

            relay.abort();
            assert!(relay.await.unwrap_err().is_cancelled());
        });

        let admission = state.admission.snapshot();
        assert_eq!(admission.global.in_use, 0);
        assert_eq!(admission.pre_routing.in_use, 0);
        assert_eq!(admission.relay.in_use, 0);
        public_peer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        match public_peer.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                ) => {}
            result => panic!("cancelled relay kept the public socket open: {result:?}"),
        }
        drop(workload);
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
                certificate: CertificateProof {
                    fingerprint: "AA:BB".to_string(),
                    not_after_unix_seconds: u64::MAX,
                },
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
    fn control_status_reports_state_and_stop_sets_shutdown() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        state
            .routes
            .write()
            .unwrap()
            .insert("www.example.com".to_string(), active_route(backend()));
        state.accepted_connections.store(7, Ordering::Relaxed);
        let shutdown = running_shutdown();
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
        assert!(status.contains("route_selection_queue_limit=56"));
        assert!(status.contains("route_selection_workers=8"));
        assert!(status.contains("connection_queue_limit=64"));
        assert!(status.contains("connection_workers=64"));

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
        assert!(shutdown.is_requested());
        let draining = render_control_response(&state, &shutdown, "STATUS");
        assert!(draining.starts_with("draining\n"));
        assert!(draining.contains("draining=true"));
        assert!(draining.contains("ready=false"));
        let draining_json = serde_json::from_str::<serde_json::Value>(&render_control_response(
            &state,
            &shutdown,
            "STATUS JSON",
        ))
        .unwrap();
        assert_eq!(draining_json["live"], true);
        assert_eq!(draining_json["draining"], true);
        assert_eq!(draining_json["ready"], false);
        let draining_metrics = render_prometheus_metrics(&state, &shutdown);
        assert!(draining_metrics.contains("phx_port_ready 0"));
        assert!(draining_metrics.contains("phx_port_draining 1"));
        assert_eq!(
            render_control_response(&state, &shutdown, "RELOAD"),
            "ERROR reload is unavailable while ingress is draining\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_profile_is_observable_and_disables_dynamic_registry_discovery() {
        let directory = tempdir().unwrap();
        let registry = write_logical_registry(
            directory.path(),
            &[("contoso-web", 4401), ("undeclared-web", 4402)],
        );
        let state = ProxyState::new_with_profile(
            registry,
            public_profile("declared.example.com", "contoso-web"),
        );

        reconcile_workloads(&state);
        assert!(state.workloads.lock().unwrap().is_empty());
        let error = resolve_backend("www.example.com", &state).unwrap_err();
        assert_eq!(
            error,
            "public ingress has no Route Declaration for www.example.com"
        );
        assert_eq!(state.successful_discoveries.load(Ordering::Relaxed), 0);

        let shutdown = running_shutdown();
        let status = render_control_response(&state, &shutdown, "STATUS");
        assert!(status.contains("hosting_profile=public"));
        assert!(status.contains("active_routes=0"));
        assert!(status.contains("declared_routes=1"));
        assert!(status.contains("required_routes=1"));
        assert!(status.contains("ready=false"));
        assert!(status.contains("degraded_routes=1"));
        assert!(status.contains("registry_valid=true"));
        assert!(status.contains("undeclared_registrations=1"));
    }

    #[cfg(unix)]
    #[test]
    fn public_route_state_is_private_and_never_modifies_stable_assignments() {
        const HOSTNAME: &str = "www.example.test";

        let directory = tempdir().unwrap();
        let state_directory = directory.path().join("state");
        fs::create_dir(&state_directory).unwrap();
        let registry = write_logical_registry(&state_directory, &[("contoso-web", 4401)]);
        let runtime = directory.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
        let route_state = state_directory.join("routes.toml");
        let paths = ProductionPaths {
            port_registry: registry.clone(),
            route_cache: route_state.clone(),
            runtime_root: runtime,
        };
        let state =
            ProxyState::new_with_production_paths(public_profile(HOSTNAME, "contoso-web"), paths);
        let assignments_before = fs::read(&registry).unwrap();
        let profile = state.hosting_profile.read().unwrap();
        let (selected_cache, storage) = state.route_cache_for_profile(&profile).unwrap();
        assert_eq!(selected_cache, route_state);
        assert_eq!(storage, route_cache::Storage::SeparateState);
        drop(profile);

        install_active_route(
            &state,
            HOSTNAME,
            ProbeMatch {
                backend: Backend {
                    project: "contoso-web".to_string(),
                    role: "https".to_string(),
                    port: 4401,
                },
                certificate: CertificateProof {
                    fingerprint: "AA:BB".to_string(),
                    not_after_unix_seconds: u64::MAX,
                },
            },
            Some(1),
        )
        .unwrap();

        assert_eq!(fs::read(&registry).unwrap(), assignments_before);
        assert!(
            fs::read_to_string(&registry)
                .unwrap()
                .parse::<toml_edit::DocumentMut>()
                .unwrap()
                .get("discovered_routes")
                .is_none()
        );
        let cached = route_cache::load(&route_state, HOSTNAME, route_cache::Storage::SeparateState)
            .unwrap()
            .unwrap();
        assert_eq!(cached.project, "contoso-web");
        assert_eq!(cached.role, "https");
        assert_eq!(
            fs::metadata(&route_state).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(state_directory.join("routes.toml.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn reload_is_atomic_and_stale_certificate_results_cannot_cross_generations() {
        let directory = tempdir().unwrap();
        let ingress_config = directory.path().join("ingress.toml");
        fs::write(
            &ingress_config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\nrequired = true\n",
        )
        .unwrap();
        let profile = HostingProfile::load(Some(ingress_config.clone())).unwrap();
        let state =
            ProxyState::new_with_profile(directory.path().join("ports.toml"), profile.clone());
        let declared_backend = Backend {
            project: "contoso-web".to_string(),
            role: "https".to_string(),
            port: 4401,
        };
        let mut active = active_route(declared_backend.clone());
        active.declaration_generation = Some(1);
        state
            .routes
            .write()
            .unwrap()
            .insert("www.example.com".to_string(), active);

        fs::write(
            &ingress_config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"DUPLICATE.example.com.\"]\nworkload = \"first-web\"\nrole = \"https\"\n\
             [ingress.hosts.\"duplicate.example.com\"]\nworkload = \"second-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        reload_public_profile(&state);
        assert_eq!(state.public_snapshot().unwrap().generation, 1);
        assert_eq!(
            state.routes.read().unwrap()["www.example.com"].declaration_generation,
            Some(1)
        );
        let rejected = render_control_response(&state, &running_shutdown(), "STATUS");
        assert!(rejected.contains("last_reload_error=config_invalid"));
        assert!(rejected.contains("last_rejected_config_generation=2"));

        fs::write(
            &ingress_config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\nrequired = false\n",
        )
        .unwrap();
        reload_public_profile(&state);
        assert_eq!(state.public_snapshot().unwrap().generation, 2);
        assert_eq!(
            state.routes.read().unwrap()["www.example.com"].declaration_generation,
            Some(2)
        );
        assert!(
            install_active_route(
                &state,
                "www.example.com",
                ProbeMatch {
                    backend: declared_backend,
                    certificate: CertificateProof {
                        fingerprint: "stale".to_string(),
                        not_after_unix_seconds: u64::MAX,
                    },
                },
                Some(1),
            )
            .unwrap_err()
            .contains("generation changed")
        );
        assert_ne!(
            state.routes.read().unwrap()["www.example.com"]
                .certificate
                .fingerprint,
            "stale"
        );

        fs::write(
            &ingress_config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"replacement-web\"\nrole = \"https\"\nrequired = true\n",
        )
        .unwrap();
        reload_public_profile(&state);
        assert_eq!(state.public_snapshot().unwrap().generation, 3);
        assert!(state.routes.read().unwrap().is_empty());
    }

    #[test]
    fn verified_routes_and_conflict_diagnostics_stop_at_fixed_bounds() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        {
            let mut routes = state.routes.write().unwrap();
            for index in 0..MAX_VERIFIED_ROUTES {
                routes.insert(
                    format!("route-{index}.example.com"),
                    active_route(backend()),
                );
            }
        }
        let error = install_active_route(
            &state,
            "overflow.example.com",
            ProbeMatch {
                backend: backend(),
                certificate: CertificateProof {
                    fingerprint: "AA:BB".to_string(),
                    not_after_unix_seconds: u64::MAX,
                },
            },
            None,
        )
        .unwrap_err();
        assert!(error.contains("verified route capacity"), "{error}");
        assert_eq!(state.routes.read().unwrap().len(), MAX_VERIFIED_ROUTES);
        assert_eq!(state.route_capacity_rejections.load(Ordering::Acquire), 1);

        {
            let mut conflicts = state.conflicts.write().unwrap();
            for index in 0..MAX_ROUTE_CONFLICTS {
                conflicts.insert(format!("conflict-{index}.example.com"), vec![backend()]);
            }
        }
        record_conflict(
            &state,
            "overflow.example.com",
            vec![backend(), {
                let mut contender = backend();
                contender.port = 4402;
                contender
            }],
        );
        assert_eq!(state.conflicts.read().unwrap().len(), MAX_ROUTE_CONFLICTS);
        assert_eq!(state.conflict_capacity_drops.load(Ordering::Acquire), 1);
        let diagnostics = render_control_response(&state, &running_shutdown(), "ROUTES");
        assert_eq!(diagnostics.lines().count(), MAX_ROUTE_DIAGNOSTICS + 1);
        assert!(
            diagnostics
                .lines()
                .last()
                .is_some_and(|line| line.starts_with("truncated\t")),
            "{diagnostics}"
        );
    }

    #[test]
    fn machine_status_bounds_degraded_route_details_and_response_bytes() {
        let directory = tempdir().unwrap();
        let routes = (0..MAX_ROUTE_DECLARATIONS)
            .map(|index| {
                let hostname = format!(
                    "r{index:04}.{}.{}.{}.{}",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(55)
                );
                (
                    hostname.clone(),
                    RouteDeclaration {
                        hostname,
                        workload: format!("w{index:04}-{}", "a".repeat(122)),
                        role: "r".repeat(128),
                        required: true,
                        relay_idle_timeout: Some(DEFAULT_RELAY_IDLE_TIMEOUT),
                    },
                )
            })
            .collect();
        let profile = HostingProfile::Public(Arc::new(PublicIngressSnapshot {
            ingress_config: directory.path().join("ingress.toml"),
            intent_owner: IntentOwner::EffectiveUser,
            generation: 1,
            listeners: None,
            metrics: None,
            source_diagnostics: None,
            routes,
        }));
        let state = ProxyState::new_with_profile(directory.path().join("ports.toml"), profile);

        let rendered = render_control_response(&state, &running_shutdown(), "STATUS JSON");
        assert!(rendered.len() as u64 <= CONTROL_RESPONSE_LIMIT);
        let status = serde_json::from_str::<serde_json::Value>(&rendered).unwrap();
        assert_eq!(
            status["degraded_routes"].as_array().unwrap().len(),
            MAX_ROUTE_DIAGNOSTICS
        );
        assert_eq!(
            status["degraded_routes_omitted"],
            MAX_ROUTE_DECLARATIONS - MAX_ROUTE_DIAGNOSTICS
        );

        let snapshot = state.public_snapshot().unwrap();
        let active_routes = snapshot
            .routes
            .iter()
            .map(|(hostname, declaration)| {
                let mut active = active_route(Backend {
                    project: declaration.workload.clone(),
                    role: declaration.role.clone(),
                    port: 4401,
                });
                active.declaration_generation = Some(snapshot.generation);
                active.certificate.not_after_unix_seconds =
                    current_unix_seconds() + 13 * 24 * 60 * 60;
                active.last_expiry_warning = Some(CertificateExpiryState::Warning14Days);
                (hostname.clone(), active)
            })
            .collect();
        *state.routes.write().unwrap() = active_routes;
        state.routes.write().unwrap().insert(
            "attacker-controlled.example".to_string(),
            active_route(backend()),
        );

        let rendered = render_control_response(&state, &running_shutdown(), "STATUS JSON");
        assert!(rendered.len() as u64 <= CONTROL_RESPONSE_LIMIT);
        let status = serde_json::from_str::<serde_json::Value>(&rendered).unwrap();
        assert_eq!(
            status["certificate_routes"].as_array().unwrap().len(),
            MAX_ROUTE_DIAGNOSTICS
        );
        assert_eq!(
            status["certificate_routes_omitted"],
            MAX_ROUTE_DECLARATIONS - MAX_ROUTE_DIAGNOSTICS
        );

        let metrics = render_prometheus_metrics(&state, &running_shutdown());
        assert!(metrics.len() <= PROMETHEUS_BODY_LIMIT);
        assert_eq!(
            metrics
                .lines()
                .filter(|line| line.starts_with("phx_port_route_state{"))
                .count(),
            MAX_ROUTE_DECLARATIONS
        );
        assert_eq!(
            metrics
                .lines()
                .filter(|line| line.starts_with("phx_port_route_certificate_not_after_seconds{"))
                .count(),
            MAX_ROUTE_DECLARATIONS
        );
        assert!(!metrics.contains("attacker-controlled.example"));
        for forbidden in [
            "source=",
            "connection_id",
            "certificate_fingerprint",
            "BEGIN CERTIFICATE",
            "private_key",
            "error=",
        ] {
            assert!(
                !metrics.contains(forbidden),
                "metrics leaked forbidden label {forbidden:?}"
            );
        }
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
            "rejected_routing_queue",
            "rejected_routing_timeout",
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

        let status = render_control_response(&state, &running_shutdown(), "STATUS");
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
    fn delivery_events_are_rate_limited_with_fixed_outcomes() {
        let directory = tempdir().unwrap();
        let state = ProxyState::new(directory.path().join("ports.toml"));
        let now = Instant::now();

        for outcome in DeliveryOutcome::ALL {
            let event = state.record_delivery_outcome_at(outcome, now).unwrap();
            assert_eq!(
                event.to_string(),
                format!(
                    "event={} result={} count=1 suppressed=0",
                    outcome.event(),
                    outcome.result()
                )
            );
            assert!(
                state
                    .record_delivery_outcome_at(outcome, now + Duration::from_millis(1))
                    .is_none()
            );
        }

        for outcome in DeliveryOutcome::ALL {
            let event = state
                .record_delivery_outcome_at(outcome, now + DELIVERY_EVENT_INTERVAL)
                .unwrap();
            assert_eq!(
                event.to_string(),
                format!(
                    "event={} result={} count=2 suppressed=1",
                    outcome.event(),
                    outcome.result()
                )
            );
        }
    }

    #[test]
    fn source_diagnostics_are_sampled_rate_limited_and_expire() {
        let directory = tempdir().unwrap();
        let profile = match public_profile("www.example.com", "contoso-web") {
            HostingProfile::Public(snapshot) => {
                let mut snapshot = (*snapshot).clone();
                snapshot.source_diagnostics = Some(SourceDiagnosticsConfig {
                    sample_every: 2,
                    expires_at_unix_seconds: 100,
                });
                HostingProfile::Public(Arc::new(snapshot))
            }
            HostingProfile::Development => unreachable!(),
        };
        let state = ProxyState::new_with_profile(directory.path().join("ports.toml"), profile);
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = Instant::now();

        assert!(
            state
                .record_source_diagnostic_at(source, "www.example.com", 50, now)
                .is_none()
        );
        assert_eq!(
            state
                .record_source_diagnostic_at(source, "www.example.com", 50, now)
                .unwrap()
                .to_string(),
            "event=source_diagnostic source=192.0.2.1 hostname=www.example.com"
        );
        assert!(
            state
                .record_source_diagnostic_at(
                    source,
                    "www.example.com",
                    50,
                    now + Duration::from_millis(1),
                )
                .is_none()
        );
        assert!(
            state
                .record_source_diagnostic_at(
                    source,
                    "www.example.com",
                    50,
                    now + Duration::from_millis(1),
                )
                .is_none()
        );
        assert!(
            state
                .record_source_diagnostic_at(
                    source,
                    "www.example.com",
                    50,
                    now + SOURCE_DIAGNOSTIC_EVENT_INTERVAL,
                )
                .is_none()
        );
        assert!(
            state
                .record_source_diagnostic_at(
                    source,
                    "www.example.com",
                    50,
                    now + SOURCE_DIAGNOSTIC_EVENT_INTERVAL,
                )
                .is_some()
        );
        assert!(
            state
                .record_source_diagnostic_at(
                    source,
                    "www.example.com",
                    100,
                    now + SOURCE_DIAGNOSTIC_EVENT_INTERVAL * 2,
                )
                .is_none()
        );
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
            certificate: CertificateProof {
                fingerprint: "MAIN".to_string(),
                not_after_unix_seconds: u64::MAX,
            },
        };
        let mut https_backend = backend();
        https_backend.role = "https".to_string();
        https_backend.port = 4402;
        let https = ProbeMatch {
            backend: https_backend.clone(),
            certificate: CertificateProof {
                fingerprint: "HTTPS".to_string(),
                not_after_unix_seconds: u64::MAX,
            },
        };
        let mut other_backend = backend();
        other_backend.project = "/other".to_string();
        other_backend.port = 4403;
        let other = ProbeMatch {
            backend: other_backend.clone(),
            certificate: CertificateProof {
                fingerprint: "OTHER".to_string(),
                not_after_unix_seconds: u64::MAX,
            },
        };

        let preferred = prefer_https_per_project(vec![main, other, https]);

        assert_eq!(preferred.len(), 2);
        assert!(preferred.iter().any(|matched| {
            matched.backend == https_backend && matched.certificate.fingerprint == "HTTPS"
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
        route_cache::store(
            &path,
            route_cache::Storage::CombinedRegistry,
            "www.example.com",
            "/project",
            "https",
            "AA:BB",
        )
        .unwrap();

        reconcile_routes(&state);

        assert!(state.routes.read().unwrap().is_empty());
        assert!(
            route_cache::load(
                &path,
                "www.example.com",
                route_cache::Storage::CombinedRegistry
            )
            .unwrap()
            .is_none()
        );
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
        route_cache::store(
            &path,
            route_cache::Storage::CombinedRegistry,
            "www.example.com",
            "/project",
            "https",
            "AA:BB",
        )
        .unwrap();

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
        assert!(
            route_cache::load(
                &path,
                "www.example.com",
                route_cache::Storage::CombinedRegistry
            )
            .unwrap()
            .is_some()
        );
    }
}
