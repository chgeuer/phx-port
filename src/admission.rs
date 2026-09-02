use crate::ingress_limits::ValidatedIngressLimits;
use std::fmt;
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
        let capacity = (burst as u128).saturating_mul(TOKEN_UNITS);
        Self {
            tokens: capacity,
            capacity,
            refill_per_second: refill_per_second as u128,
            last_refill: Instant::now(),
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

pub(crate) struct PreRoutingAdmission {
    global: GlobalIngressPermit,
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
    PreRouting,
    Relay,
    Handoff,
}

impl fmt::Display for AdmissionRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AcceptRate => "global accept rate exhausted",
            Self::Global => "global ingress capacity exhausted",
            Self::PreRouting => "pre-routing capacity exhausted",
            Self::Relay => "relay capacity exhausted",
            Self::Handoff => "handoff negotiation capacity exhausted",
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
                global: Capacity::new(limits.active_connections()),
                pre_routing: Capacity::new(limits.pre_routing_connections()),
                relay: Capacity::new(limits.relay_connections()),
                handoff: Capacity::new(limits.handoff_negotiations()),
            }),
        }
    }

    pub(crate) fn try_admit(&self) -> Result<PreRoutingAdmission, AdmissionRejection> {
        self.try_admit_at(Instant::now())
    }

    fn try_admit_at(&self, now: Instant) -> Result<PreRoutingAdmission, AdmissionRejection> {
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
        let pre_routing = PreRoutingPermit {
            _permit: self
                .try_acquire(CapacityKind::PreRouting)
                .ok_or(AdmissionRejection::PreRouting)?,
        };
        Ok(PreRoutingAdmission {
            global,
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
        AdmissionSnapshot {
            global: self.snapshot_capacity(CapacityKind::Global),
            pre_routing: self.snapshot_capacity(CapacityKind::PreRouting),
            relay: self.snapshot_capacity(CapacityKind::Relay),
            handoff: self.snapshot_capacity(CapacityKind::Handoff),
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
            pre_routing,
        } = self;
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
    use crate::ingress_limits::{IngressLimits, SystemCapacity};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

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

    #[test]
    fn global_and_pre_routing_limits_are_exact_and_release_on_drop() {
        let admission = controller(2, 1, 1, 1);
        let first = admission.try_admit().unwrap();

        assert!(matches!(
            admission.try_admit(),
            Err(AdmissionRejection::PreRouting)
        ));
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.global.in_use, 1);
        assert_eq!(snapshot.pre_routing.in_use, 1);

        drop(first);
        let first = admission.try_admit().unwrap();
        let second_controller = controller(1, 1, 1, 1);
        let only = second_controller.try_admit().unwrap();
        assert!(matches!(
            second_controller.try_admit(),
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

        drop(admission.try_admit_at(now).unwrap());
        assert!(matches!(
            admission.try_admit_at(now),
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
                let permit = admission.try_admit().ok();
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
        let first = admission.try_admit().unwrap();
        let relay = admission.try_acquire_relay().unwrap();
        let first = first.into_relay(relay);

        let snapshot = admission.snapshot();
        assert_eq!(snapshot.global.in_use, 1);
        assert_eq!(snapshot.pre_routing.in_use, 0);
        assert_eq!(snapshot.relay.in_use, 1);

        let second = admission.try_admit().unwrap();
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
                let routing = admission.try_admit().unwrap();
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
}
