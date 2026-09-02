use crate::ingress_limits::{SourceLimits, ValidatedIngressLimits};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TOKEN_UNITS: u128 = 1_000_000_000;

#[derive(Clone)]
pub(crate) struct AdmissionController {
    state: Arc<AdmissionState>,
}

struct AdmissionState {
    accept_rate: Mutex<TokenBucket>,
    sources: Mutex<SourceTable>,
    global: Capacity,
    pre_routing: Capacity,
    relay: Capacity,
    handoff: Capacity,
}

struct Capacity {
    in_use: AtomicUsize,
    limit: usize,
}

struct TokenBucket {
    tokens: u128,
    capacity: u128,
    refill_per_second: u128,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(refill_per_second: usize, burst: usize) -> Self {
        Self::new_at(refill_per_second, burst, Instant::now())
    }

    fn new_at(refill_per_second: usize, burst: usize, now: Instant) -> Self {
        let capacity = (burst as u128).saturating_mul(TOKEN_UNITS);
        Self {
            tokens: capacity,
            capacity,
            refill_per_second: refill_per_second as u128,
            last_refill: now,
        }
    }

    fn try_take_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        self.try_take_after(elapsed)
    }

    fn try_take_after(&mut self, elapsed: Duration) -> bool {
        let refill = elapsed.as_nanos().saturating_mul(self.refill_per_second);
        self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
        if self.tokens < TOKEN_UNITS {
            return false;
        }
        self.tokens -= TOKEN_UNITS;
        true
    }
}

#[derive(Clone, Copy)]
struct SourcePolicy {
    accepts_per_second: usize,
    accept_burst: usize,
    pre_routing_connections: usize,
    ipv6_prefix: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum SourceNetwork {
    V4(u32),
    V6 { network: u128, prefix: u8 },
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct SourceKey {
    policy_id: usize,
    network: SourceNetwork,
}

struct SourceEntry {
    rate: TokenBucket,
    pre_routing: usize,
    pre_routing_limit: usize,
    last_seen: Instant,
}

struct SourceTable {
    limits: SourceLimits,
    entries: HashMap<SourceKey, SourceEntry>,
    age: BTreeSet<(Instant, SourceKey)>,
}

impl SourceTable {
    fn new(limits: &SourceLimits) -> Self {
        Self {
            limits: limits.clone(),
            entries: HashMap::new(),
            age: BTreeSet::new(),
        }
    }

    fn try_acquire(
        &mut self,
        address: IpAddr,
        now: Instant,
    ) -> Result<SourceKey, AdmissionRejection> {
        self.evict_expired(now);
        let (key, policy) = self.key_and_policy(address);
        if !self.entries.contains_key(&key) {
            self.make_room()?;
            self.entries.insert(
                key,
                SourceEntry {
                    rate: TokenBucket::new_at(policy.accepts_per_second, policy.accept_burst, now),
                    pre_routing: 0,
                    pre_routing_limit: policy.pre_routing_connections,
                    last_seen: now,
                },
            );
            self.age.insert((now, key));
        }

        let entry = self
            .entries
            .get_mut(&key)
            .expect("source entry was inserted before admission");
        self.age.remove(&(entry.last_seen, key));
        entry.last_seen = now;
        self.age.insert((now, key));
        if !entry.rate.try_take_at(now) {
            return Err(AdmissionRejection::SourceRate);
        }
        if entry.pre_routing >= entry.pre_routing_limit {
            return Err(AdmissionRejection::SourceConcurrency);
        }
        entry.pre_routing += 1;
        Ok(key)
    }

    fn release(&mut self, key: SourceKey) {
        let Some(entry) = self.entries.get_mut(&key) else {
            debug_assert!(false, "active source permit lost its table entry");
            return;
        };
        debug_assert!(entry.pre_routing > 0);
        entry.pre_routing = entry.pre_routing.saturating_sub(1);
    }

    fn evict_expired(&mut self, now: Instant) {
        let ttl = Duration::from_secs(self.limits.entry_ttl_seconds);
        while let Some((last_seen, key)) = self.age.first().copied() {
            if now.saturating_duration_since(last_seen) < ttl {
                break;
            }
            self.age.pop_first();
            let Some(entry) = self.entries.get_mut(&key) else {
                debug_assert!(false, "source age index referenced a missing entry");
                continue;
            };
            if entry.pre_routing == 0 {
                self.entries.remove(&key);
            } else {
                entry.last_seen = now;
                self.age.insert((now, key));
            }
        }
    }

    fn make_room(&mut self) -> Result<(), AdmissionRejection> {
        if self.entries.len() < self.limits.table_capacity {
            return Ok(());
        }
        let victim = self.age.iter().find_map(|(last_seen, key)| {
            self.entries
                .get(key)
                .is_some_and(|entry| entry.pre_routing == 0)
                .then_some((*last_seen, *key))
        });
        let Some((last_seen, key)) = victim else {
            return Err(AdmissionRejection::SourceStateCapacity);
        };
        self.age.remove(&(last_seen, key));
        self.entries.remove(&key);
        Ok(())
    }

    fn key_and_policy(&self, address: IpAddr) -> (SourceKey, SourcePolicy) {
        let selected = self
            .limits
            .overrides
            .iter()
            .enumerate()
            .filter(|(_, policy)| policy.cidr.contains(address))
            .max_by_key(|(_, policy)| policy.cidr.prefix());
        let (policy_id, policy) = match selected {
            Some((index, selected)) => (
                index + 1,
                SourcePolicy {
                    accepts_per_second: selected.accepts_per_second,
                    accept_burst: selected.accept_burst,
                    pre_routing_connections: selected.pre_routing_connections,
                    ipv6_prefix: selected
                        .ipv6_prefix
                        .unwrap_or(self.limits.ipv6_prefix)
                        .max(selected.cidr.prefix()),
                },
            ),
            None => (
                0,
                SourcePolicy {
                    accepts_per_second: self.limits.accepts_per_second,
                    accept_burst: self.limits.accept_burst,
                    pre_routing_connections: self.limits.pre_routing_connections,
                    ipv6_prefix: self.limits.ipv6_prefix,
                },
            ),
        };
        let network = match address {
            IpAddr::V4(address) => SourceNetwork::V4(u32::from(address)),
            IpAddr::V6(address) => {
                let prefix = policy.ipv6_prefix;
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                SourceNetwork::V6 {
                    network: u128::from(address) & mask,
                    prefix,
                }
            }
        };
        (SourceKey { policy_id, network }, policy)
    }
}

impl Capacity {
    fn new(limit: usize) -> Self {
        Self {
            in_use: AtomicUsize::new(0),
            limit,
        }
    }
}

#[derive(Clone, Copy)]
enum CapacityKind {
    Global,
    PreRouting,
    Relay,
    Handoff,
}

struct CapacityPermit {
    state: Arc<AdmissionState>,
    kind: CapacityKind,
}

impl Drop for CapacityPermit {
    fn drop(&mut self) {
        let previous = self
            .state
            .capacity(self.kind)
            .in_use
            .fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

pub(crate) struct GlobalIngressPermit {
    _permit: CapacityPermit,
}

pub(crate) struct PreRoutingPermit {
    _permit: CapacityPermit,
}

pub(crate) struct RelayPermit {
    _permit: CapacityPermit,
}

pub(crate) struct HandoffNegotiationPermit {
    _permit: CapacityPermit,
}

pub(crate) struct SourcePermit {
    state: Arc<AdmissionState>,
    key: SourceKey,
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        let mut sources = self
            .state
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sources.release(self.key);
    }
}

pub(crate) struct PreRoutingAdmission {
    global: GlobalIngressPermit,
    source: SourcePermit,
    pre_routing: PreRoutingPermit,
}

pub(crate) struct RelayAdmission {
    _global: GlobalIngressPermit,
    _relay: RelayPermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionRejection {
    AcceptRate,
    Global,
    SourceRate,
    SourceConcurrency,
    SourceStateCapacity,
    PreRouting,
    Relay,
    Handoff,
    RoutingQueue,
    RoutingTimeout,
}

impl AdmissionRejection {
    pub(crate) const COUNT: usize = 10;

    #[cfg(test)]
    pub(crate) const ALL: [Self; Self::COUNT] = [
        Self::AcceptRate,
        Self::Global,
        Self::SourceRate,
        Self::SourceConcurrency,
        Self::SourceStateCapacity,
        Self::PreRouting,
        Self::Relay,
        Self::Handoff,
        Self::RoutingQueue,
        Self::RoutingTimeout,
    ];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::AcceptRate => 0,
            Self::Global => 1,
            Self::SourceRate => 2,
            Self::SourceConcurrency => 3,
            Self::SourceStateCapacity => 4,
            Self::PreRouting => 5,
            Self::Relay => 6,
            Self::Handoff => 7,
            Self::RoutingQueue => 8,
            Self::RoutingTimeout => 9,
        }
    }

    pub(crate) const fn event_reason(self) -> &'static str {
        match self {
            Self::AcceptRate => "accept_rate",
            Self::Global => "global_capacity",
            Self::SourceRate => "source_rate",
            Self::SourceConcurrency => "source_concurrency",
            Self::SourceStateCapacity => "source_state_capacity",
            Self::PreRouting => "pre_routing_capacity",
            Self::Relay => "relay_capacity",
            Self::Handoff => "handoff_capacity",
            Self::RoutingQueue => "routing_queue",
            Self::RoutingTimeout => "routing_timeout",
        }
    }
}

impl fmt::Display for AdmissionRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AcceptRate => "global accept rate exhausted",
            Self::Global => "global ingress capacity exhausted",
            Self::SourceRate => "source accept rate exhausted",
            Self::SourceConcurrency => "source pre-routing capacity exhausted",
            Self::SourceStateCapacity => "source state capacity exhausted",
            Self::PreRouting => "pre-routing capacity exhausted",
            Self::Relay => "relay capacity exhausted",
            Self::Handoff => "handoff negotiation capacity exhausted",
            Self::RoutingQueue => "route-selection queue capacity exhausted",
            Self::RoutingTimeout => "route selection timed out",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapacitySnapshot {
    pub(crate) in_use: usize,
    pub(crate) limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionSnapshot {
    pub(crate) global: CapacitySnapshot,
    pub(crate) pre_routing: CapacitySnapshot,
    pub(crate) relay: CapacitySnapshot,
    pub(crate) handoff: CapacitySnapshot,
    pub(crate) source_entries: usize,
    pub(crate) source_entry_limit: usize,
}

impl AdmissionState {
    fn capacity(&self, kind: CapacityKind) -> &Capacity {
        match kind {
            CapacityKind::Global => &self.global,
            CapacityKind::PreRouting => &self.pre_routing,
            CapacityKind::Relay => &self.relay,
            CapacityKind::Handoff => &self.handoff,
        }
    }
}

impl AdmissionController {
    pub(crate) fn new(limits: &ValidatedIngressLimits) -> Self {
        Self {
            state: Arc::new(AdmissionState {
                accept_rate: Mutex::new(TokenBucket::new(
                    limits.accepts_per_second(),
                    limits.accept_burst(),
                )),
                sources: Mutex::new(SourceTable::new(limits.source())),
                global: Capacity::new(limits.active_connections()),
                pre_routing: Capacity::new(limits.pre_routing_connections()),
                relay: Capacity::new(limits.relay_connections()),
                handoff: Capacity::new(limits.handoff_negotiations()),
            }),
        }
    }

    pub(crate) fn try_admit(
        &self,
        source: IpAddr,
    ) -> Result<PreRoutingAdmission, AdmissionRejection> {
        self.try_admit_at(source, Instant::now())
    }

    fn try_admit_at(
        &self,
        source: IpAddr,
        now: Instant,
    ) -> Result<PreRoutingAdmission, AdmissionRejection> {
        let accepted = self
            .state
            .accept_rate
            .lock()
            .map(|mut bucket| bucket.try_take_at(now))
            .unwrap_or(false);
        if !accepted {
            return Err(AdmissionRejection::AcceptRate);
        }
        let global = GlobalIngressPermit {
            _permit: self
                .try_acquire(CapacityKind::Global)
                .ok_or(AdmissionRejection::Global)?,
        };
        let source = SourcePermit {
            key: self
                .state
                .sources
                .lock()
                .map_err(|_| AdmissionRejection::SourceStateCapacity)?
                .try_acquire(source, now)?,
            state: Arc::clone(&self.state),
        };
        let pre_routing = PreRoutingPermit {
            _permit: self
                .try_acquire(CapacityKind::PreRouting)
                .ok_or(AdmissionRejection::PreRouting)?,
        };
        Ok(PreRoutingAdmission {
            global,
            source,
            pre_routing,
        })
    }

    pub(crate) fn try_acquire_relay(&self) -> Result<RelayPermit, AdmissionRejection> {
        self.try_acquire(CapacityKind::Relay)
            .map(|permit| RelayPermit { _permit: permit })
            .ok_or(AdmissionRejection::Relay)
    }

    pub(crate) fn try_acquire_handoff(
        &self,
    ) -> Result<HandoffNegotiationPermit, AdmissionRejection> {
        self.try_acquire(CapacityKind::Handoff)
            .map(|permit| HandoffNegotiationPermit { _permit: permit })
            .ok_or(AdmissionRejection::Handoff)
    }

    pub(crate) fn snapshot(&self) -> AdmissionSnapshot {
        let sources = self
            .state
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let source_entries = sources.entries.len();
        let source_entry_limit = sources.limits.table_capacity;
        drop(sources);
        AdmissionSnapshot {
            global: self.snapshot_capacity(CapacityKind::Global),
            pre_routing: self.snapshot_capacity(CapacityKind::PreRouting),
            relay: self.snapshot_capacity(CapacityKind::Relay),
            handoff: self.snapshot_capacity(CapacityKind::Handoff),
            source_entries,
            source_entry_limit,
        }
    }

    fn try_acquire(&self, kind: CapacityKind) -> Option<CapacityPermit> {
        let capacity = self.state.capacity(kind);
        capacity
            .in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < capacity.limit).then_some(current + 1)
            })
            .ok()?;
        Some(CapacityPermit {
            state: Arc::clone(&self.state),
            kind,
        })
    }

    fn snapshot_capacity(&self, kind: CapacityKind) -> CapacitySnapshot {
        let capacity = self.state.capacity(kind);
        CapacitySnapshot {
            in_use: capacity.in_use.load(Ordering::Acquire),
            limit: capacity.limit,
        }
    }
}

impl PreRoutingAdmission {
    pub(crate) fn into_relay(self, relay: RelayPermit) -> RelayAdmission {
        let Self {
            global,
            source,
            pre_routing,
        } = self;
        drop(source);
        drop(pre_routing);
        RelayAdmission {
            _global: global,
            _relay: relay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionController, AdmissionRejection, TokenBucket};
    use crate::ingress_limits::{
        IngressLimits, SourceCidr, SourceLimitOverride, SourceLimits, SystemCapacity,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn controller(
        active_connections: usize,
        pre_routing_connections: usize,
        relay_connections: usize,
        handoff_negotiations: usize,
    ) -> AdmissionController {
        let limits = IngressLimits {
            active_connections,
            pre_routing_connections,
            relay_connections,
            handoff_negotiations,
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
        AdmissionController::new(&limits)
    }

    fn controller_with_source(
        active_connections: usize,
        pre_routing_connections: usize,
        relay_connections: usize,
        source: SourceLimits,
    ) -> AdmissionController {
        let limits = IngressLimits {
            active_connections,
            pre_routing_connections,
            relay_connections,
            handoff_negotiations: 1,
            source,
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
        AdmissionController::new(&limits)
    }

    #[test]
    fn global_and_pre_routing_limits_are_exact_and_release_on_drop() {
        let admission = controller(2, 1, 1, 1);
        let first = admission.try_admit(SOURCE).unwrap();

        assert!(matches!(
            admission.try_admit(SOURCE),
            Err(AdmissionRejection::PreRouting)
        ));
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.global.in_use, 1);
        assert_eq!(snapshot.pre_routing.in_use, 1);

        drop(first);
        let first = admission.try_admit(SOURCE).unwrap();
        let second_controller = controller(1, 1, 1, 1);
        let only = second_controller.try_admit(SOURCE).unwrap();
        assert!(matches!(
            second_controller.try_admit(SOURCE),
            Err(AdmissionRejection::Global)
        ));

        drop((first, only));
        assert_eq!(admission.snapshot().global.in_use, 0);
        assert_eq!(admission.snapshot().pre_routing.in_use, 0);
        assert_eq!(second_controller.snapshot().global.in_use, 0);
    }

    #[test]
    fn global_accept_bucket_enforces_burst_and_fractional_refill() {
        let mut bucket = TokenBucket::new(2, 3);
        assert!(bucket.try_take_after(Duration::ZERO));
        assert!(bucket.try_take_after(Duration::ZERO));
        assert!(bucket.try_take_after(Duration::ZERO));
        assert!(!bucket.try_take_after(Duration::ZERO));

        assert!(!bucket.try_take_after(Duration::from_millis(499)));
        assert!(bucket.try_take_after(Duration::from_millis(1)));
        assert!(!bucket.try_take_after(Duration::ZERO));
        assert!(bucket.try_take_after(Duration::from_secs(10)));
        assert!(bucket.try_take_after(Duration::ZERO));
        assert!(bucket.try_take_after(Duration::ZERO));
        assert!(!bucket.try_take_after(Duration::ZERO));
    }

    #[test]
    fn admission_controller_applies_the_global_accept_bucket() {
        let limits = IngressLimits {
            active_connections: 1,
            pre_routing_connections: 1,
            relay_connections: 1,
            handoff_negotiations: 1,
            accepts_per_second: 1,
            accept_burst: 1,
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
        let admission = AdmissionController::new(&limits);
        let now = std::time::Instant::now();

        drop(admission.try_admit_at(SOURCE, now).unwrap());
        assert!(matches!(
            admission.try_admit_at(SOURCE, now),
            Err(AdmissionRejection::AcceptRate)
        ));
    }

    #[test]
    fn handoff_limit_is_exact_and_releases_on_drop() {
        let admission = controller(2, 2, 1, 1);
        let permit = admission.try_acquire_handoff().unwrap();
        assert!(matches!(
            admission.try_acquire_handoff(),
            Err(AdmissionRejection::Handoff)
        ));
        assert_eq!(admission.snapshot().handoff.in_use, 1);

        drop(permit);
        assert_eq!(admission.snapshot().handoff.in_use, 0);
        assert!(admission.try_acquire_handoff().is_ok());
    }

    #[test]
    fn concurrent_admission_never_exceeds_the_exact_limit() {
        let admission = Arc::new(controller(8, 8, 8, 8));
        let start = Arc::new(Barrier::new(33));
        let attempted = Arc::new(Barrier::new(33));
        let release = Arc::new(Barrier::new(33));
        let admitted = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();

        for _ in 0..32 {
            let admission = Arc::clone(&admission);
            let start = Arc::clone(&start);
            let attempted = Arc::clone(&attempted);
            let release = Arc::clone(&release);
            let admitted = Arc::clone(&admitted);
            workers.push(thread::spawn(move || {
                start.wait();
                let permit = admission.try_admit(SOURCE).ok();
                if permit.is_some() {
                    admitted.fetch_add(1, Ordering::AcqRel);
                }
                attempted.wait();
                release.wait();
                drop(permit);
            }));
        }

        start.wait();
        attempted.wait();
        assert_eq!(admitted.load(Ordering::Acquire), 8);
        assert_eq!(admission.snapshot().global.in_use, 8);
        assert_eq!(admission.snapshot().pre_routing.in_use, 8);
        release.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(admission.snapshot().global.in_use, 0);
        assert_eq!(admission.snapshot().pre_routing.in_use, 0);
    }

    #[test]
    fn relay_transition_releases_pre_routing_but_retains_global_capacity() {
        let admission = controller(2, 2, 1, 1);
        let first = admission.try_admit(SOURCE).unwrap();
        let relay = admission.try_acquire_relay().unwrap();
        let first = first.into_relay(relay);

        let snapshot = admission.snapshot();
        assert_eq!(snapshot.global.in_use, 1);
        assert_eq!(snapshot.pre_routing.in_use, 0);
        assert_eq!(snapshot.relay.in_use, 1);

        let second = admission.try_admit(SOURCE).unwrap();
        assert!(matches!(
            admission.try_acquire_relay(),
            Err(AdmissionRejection::Relay)
        ));
        drop(second);
        assert_eq!(admission.snapshot().global.in_use, 1);

        drop(first);
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.global.in_use, 0);
        assert_eq!(snapshot.relay.in_use, 0);
    }

    #[test]
    fn panic_unwinding_releases_every_held_permit() {
        let admission = controller(1, 1, 1, 1);
        let result = std::panic::catch_unwind({
            let admission = admission.clone();
            move || {
                let routing = admission.try_admit(SOURCE).unwrap();
                let relay = admission.try_acquire_relay().unwrap();
                let _relay = routing.into_relay(relay);
                panic!("simulated connection worker panic");
            }
        });

        assert!(result.is_err());
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.global.in_use, 0);
        assert_eq!(snapshot.pre_routing.in_use, 0);
        assert_eq!(snapshot.relay.in_use, 0);
    }

    #[test]
    fn source_rate_uses_a_deterministic_fake_clock() {
        let source = SourceLimits {
            accepts_per_second: 2,
            accept_burst: 3,
            ..SourceLimits::default()
        };
        let admission = controller_with_source(8, 8, 8, source);
        let now = Instant::now();

        for _ in 0..3 {
            drop(admission.try_admit_at(SOURCE, now).unwrap());
        }
        assert!(matches!(
            admission.try_admit_at(SOURCE, now),
            Err(AdmissionRejection::SourceRate)
        ));
        assert!(matches!(
            admission.try_admit_at(SOURCE, now + Duration::from_millis(499)),
            Err(AdmissionRejection::SourceRate)
        ));
        drop(
            admission
                .try_admit_at(SOURCE, now + Duration::from_millis(500))
                .unwrap(),
        );
    }

    #[test]
    fn ipv4_is_exact_and_ipv6_uses_the_configured_prefix() {
        let source = SourceLimits {
            accepts_per_second: 1,
            accept_burst: 1,
            ipv6_prefix: 48,
            ..SourceLimits::default()
        };
        let admission = controller_with_source(8, 8, 8, source);
        let now = Instant::now();
        let ipv4_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ipv4_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        drop(admission.try_admit_at(ipv4_a, now).unwrap());
        drop(admission.try_admit_at(ipv4_b, now).unwrap());
        assert!(matches!(
            admission.try_admit_at(ipv4_a, now),
            Err(AdmissionRejection::SourceRate)
        ));

        let ipv6_a = IpAddr::V6("2001:db8:1:1::1".parse::<Ipv6Addr>().unwrap());
        let ipv6_same_48 = IpAddr::V6("2001:db8:1:2::1".parse::<Ipv6Addr>().unwrap());
        let ipv6_other_48 = IpAddr::V6("2001:db8:2::1".parse::<Ipv6Addr>().unwrap());
        drop(admission.try_admit_at(ipv6_a, now).unwrap());
        assert!(matches!(
            admission.try_admit_at(ipv6_same_48, now),
            Err(AdmissionRejection::SourceRate)
        ));
        drop(admission.try_admit_at(ipv6_other_48, now).unwrap());
    }

    #[test]
    fn longest_cidr_policy_override_controls_rate_and_ipv6_grouping() {
        let source = SourceLimits {
            accepts_per_second: 1,
            accept_burst: 1,
            overrides: vec![
                SourceLimitOverride {
                    cidr: SourceCidr::parse("10.0.0.0/8").unwrap(),
                    accepts_per_second: 2,
                    accept_burst: 2,
                    pre_routing_connections: 16,
                    ipv6_prefix: None,
                },
                SourceLimitOverride {
                    cidr: SourceCidr::parse("10.1.0.0/16").unwrap(),
                    accepts_per_second: 3,
                    accept_burst: 3,
                    pre_routing_connections: 16,
                    ipv6_prefix: None,
                },
                SourceLimitOverride {
                    cidr: SourceCidr::parse("2001:db8::/32").unwrap(),
                    accepts_per_second: 1,
                    accept_burst: 1,
                    pre_routing_connections: 16,
                    ipv6_prefix: Some(48),
                },
            ],
            ..SourceLimits::default()
        };
        let admission = controller_with_source(16, 16, 16, source);
        let now = Instant::now();
        let nested = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        for _ in 0..3 {
            drop(admission.try_admit_at(nested, now).unwrap());
        }
        assert!(matches!(
            admission.try_admit_at(nested, now),
            Err(AdmissionRejection::SourceRate)
        ));

        let ipv6_a = IpAddr::V6("2001:db8:1:1::1".parse::<Ipv6Addr>().unwrap());
        let ipv6_same_48 = IpAddr::V6("2001:db8:1:2::1".parse::<Ipv6Addr>().unwrap());
        drop(admission.try_admit_at(ipv6_a, now).unwrap());
        assert!(matches!(
            admission.try_admit_at(ipv6_same_48, now),
            Err(AdmissionRejection::SourceRate)
        ));
    }

    #[test]
    fn source_table_expires_entries_and_never_exceeds_its_limit() {
        let source = SourceLimits {
            table_capacity: 2,
            entry_ttl_seconds: 5,
            ..SourceLimits::default()
        };
        let admission = controller_with_source(8, 8, 8, source);
        let now = Instant::now();
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let third = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

        drop(admission.try_admit_at(first, now).unwrap());
        drop(
            admission
                .try_admit_at(second, now + Duration::from_secs(1))
                .unwrap(),
        );
        assert_eq!(admission.snapshot().source_entries, 2);
        drop(
            admission
                .try_admit_at(third, now + Duration::from_secs(6))
                .unwrap(),
        );
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.source_entries, 1);
        assert_eq!(snapshot.source_entry_limit, 2);
    }

    #[test]
    fn full_source_table_rejects_when_every_entry_is_active() {
        let source = SourceLimits {
            table_capacity: 1,
            ..SourceLimits::default()
        };
        let admission = controller_with_source(8, 8, 8, source);
        let first_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let first = admission.try_admit(first_source).unwrap();
        assert!(matches!(
            admission.try_admit(second_source),
            Err(AdmissionRejection::SourceStateCapacity)
        ));

        drop(first);
        assert!(admission.try_admit(second_source).is_ok());
        assert_eq!(admission.snapshot().source_entries, 1);
    }

    #[test]
    fn relay_transition_releases_source_capacity_for_more_than_sixteen_relays() {
        let admission = controller_with_source(32, 32, 32, SourceLimits::default());
        let mut relays = Vec::new();

        for _ in 0..17 {
            let routing = admission.try_admit(SOURCE).unwrap();
            let relay = admission.try_acquire_relay().unwrap();
            relays.push(routing.into_relay(relay));
        }

        let snapshot = admission.snapshot();
        assert_eq!(snapshot.global.in_use, 17);
        assert_eq!(snapshot.pre_routing.in_use, 0);
        assert_eq!(snapshot.relay.in_use, 17);
        drop(relays);
        assert_eq!(admission.snapshot().global.in_use, 0);
    }
}
