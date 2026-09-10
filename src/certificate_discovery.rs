use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    RegistryInvalid,
    WorkloadCapacity,
    ClaimStateUnavailable,
    ClaimCapacity,
}

impl Failure {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::RegistryInvalid => "registry_invalid",
            Self::WorkloadCapacity => "discovery_workload_capacity_exhausted",
            Self::ClaimStateUnavailable => "ownership_state_unavailable",
            Self::ClaimCapacity => "ownership_claim_capacity_exhausted",
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    pub generation: u64,
    // Once established, the durable namespace must also survive policy reloads.
    pub initialized: bool,
    pub reconciled: bool,
    pub error: Option<Failure>,
    pub claims: route_claims::Claims,
    pub assignments: port_registry::LogicalAssignments,
    pub observed_workloads: usize,
    checked: BTreeMap<Backend, Instant>,
    catalog_failures: BTreeMap<Backend, &'static str>,
    catalog_cursor: usize,
}

impl State {
    pub(super) fn selects(
        &self,
        hostname: &str,
        pattern: &str,
        backend: &Backend,
        generation: u64,
    ) -> bool {
        self.owns(pattern, backend, generation)
            && self
                .claims
                .matching(hostname)
                .is_some_and(|(selected, _)| selected == pattern)
    }

    pub(super) fn owns(&self, pattern: &str, backend: &Backend, generation: u64) -> bool {
        self.initialized
            && self.generation == generation
            && self.error.is_none()
            && backend.role == "https"
            && self
                .assignments
                .get(&(backend.project.clone(), backend.role.clone()))
                == Some(&backend.port)
            && self
                .claims
                .routes
                .get(pattern)
                .is_some_and(|owners| owners.len() == 1 && owners.contains(&backend.project))
    }

    pub(super) fn active(
        &self,
        pattern: &str,
        active: &ActiveRoute,
        generation: u64,
        now: u64,
    ) -> bool {
        active.declaration_generation == Some(generation)
            && active.certificate_is_valid_at(now)
            && self.owns(pattern, &active.backend, generation)
    }

    pub(super) fn readiness_reason(&self, active: usize, registry_valid: bool) -> &'static str {
        if !registry_valid {
            return "registry_invalid";
        }
        if let Some(error) = self.error {
            return error.label();
        }
        if !self.initialized || !self.reconciled {
            return "discovery_pending";
        }
        if self.claims.conflict_count() > 0 {
            return "ownership_conflict";
        }
        if active == 0 {
            return "no_verified_routes";
        }
        "ready"
    }
}

fn fail(state: &ProxyState, failure: Failure) {
    let mut discovery = state
        .certificate_discovery
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if discovery.error != Some(failure) {
        eprintln!(
            "event=certificate_discovery result=blocked reason={}",
            failure.label()
        );
    }
    discovery.error = Some(failure);
}

fn check_generation(state: &ProxyState, snapshot: &PublicIngressSnapshot) -> Result<(), String> {
    if state.public_snapshot().is_none_or(|current| {
        current.generation != snapshot.generation
            || current.routing_policy != RoutingPolicy::CertificateDiscovery
    }) {
        return Err("certificate discovery policy changed while proof was pending".into());
    }
    Ok(())
}

fn assignments_until(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    deadline: Instant,
) -> Result<port_registry::LogicalAssignments, String> {
    let assignments = load_public_registry_until(state, snapshot, deadline).inspect_err(|_| {
        fail(state, Failure::RegistryInvalid);
    })?;
    let assignments = assignments
        .into_iter()
        .filter(|((_, role), _)| role == "https")
        .collect::<port_registry::LogicalAssignments>();
    state
        .certificate_discovery
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .observed_workloads = assignments.len();
    if assignments.len() > route_claims::MAX_DISCOVERY_WORKLOADS {
        fail(state, Failure::WorkloadCapacity);
        return Err(format!(
            "certificate_discovery supports at most {} registered HTTPS Workloads; refusing a partial candidate set",
            route_claims::MAX_DISCOVERY_WORKLOADS,
        ));
    }
    Ok(assignments)
}

fn backends(assignments: &port_registry::LogicalAssignments) -> Vec<Backend> {
    assignments
        .iter()
        .map(|((project, role), port)| Backend {
            project: project.clone(),
            role: role.clone(),
            port: *port,
        })
        .collect()
}

fn claim_path(state: &ProxyState) -> Result<PathBuf, String> {
    state
        .production_paths
        .as_ref()
        .map(ProductionPaths::ownership_claims)
        .ok_or_else(|| "certificate_discovery requires protected production paths".to_string())
}

fn publish_claims(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    claims: route_claims::Claims,
    assignments: port_registry::LogicalAssignments,
) {
    let candidates = backends(&assignments);
    {
        let mut discovery = state
            .certificate_discovery
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if discovery.generation != snapshot.generation {
            discovery.checked.clear();
            discovery.reconciled = false;
        }
        if discovery.assignments != assignments {
            discovery.reconciled = false;
            state
                .negative
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
        discovery
            .checked
            .retain(|backend, _| candidates.contains(backend));
        discovery
            .catalog_failures
            .retain(|backend, _| candidates.contains(backend));
        discovery.initialized = true;
        discovery.generation = snapshot.generation;
        discovery.claims = claims.clone();
        discovery.assignments = assignments.clone();
        let error = if claims.saturated_workloads.is_empty() {
            None
        } else {
            Some(Failure::ClaimCapacity)
        };
        if discovery.error != error {
            match error {
                Some(error) => eprintln!(
                    "event=certificate_discovery result=blocked reason={}",
                    error.label()
                ),
                None => eprintln!("event=certificate_discovery result=recovered"),
            }
        }
        discovery.error = error;
    }
    state
        .routes
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|pattern, active| {
            let keep = active.declaration_generation == Some(snapshot.generation)
                && assignments.get(&(active.backend.project.clone(), active.backend.role.clone()))
                    == Some(&active.backend.port)
                && claims.routes.get(pattern).is_some_and(|owners| {
                    owners.len() == 1 && owners.contains(&active.backend.project)
                });
            if !keep {
                eprintln!(
                    "event=route result=deactivated hostname={pattern} reason=ownership_changed"
                );
            }
            keep
        });
    state
        .conflicts
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|pattern, _| {
            claims
                .routes
                .get(pattern)
                .is_some_and(|owners| owners.len() > 1)
        });
    for (pattern, owners) in &claims.routes {
        if owners.len() > 1 {
            record_conflict(
                state,
                pattern,
                candidates
                    .iter()
                    .filter(|backend| owners.contains(&backend.project))
                    .cloned()
                    .collect(),
            );
        }
    }
    state
        .route_failures
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|pattern, _| claims.routes.contains_key(pattern));
}

fn synchronise(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    deadline: Instant,
) -> Result<Vec<Backend>, String> {
    let _transaction = state.cache_transaction_until(deadline)?;
    check_generation(state, snapshot)?;
    let assignments = assignments_until(state, snapshot, deadline)?;
    let initialized = state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .initialized;
    let claims = claim_path(state)
        .and_then(|path| {
            if initialized {
                route_claims::update_existing_until(
                    &path,
                    Some(state.access_deadline(deadline)),
                    |claims| {
                        claims.retain_registrations(&assignments);
                    },
                )
            } else {
                route_claims::update_until(&path, Some(state.access_deadline(deadline)), |claims| {
                    claims.retain_registrations(&assignments);
                })
            }
        })
        .inspect_err(|_| fail(state, Failure::ClaimStateUnavailable))?;
    let candidates = backends(&assignments);
    publish_claims(state, snapshot, claims, assignments);
    Ok(candidates)
}

struct Proof {
    pattern: String,
    matched: ProbeMatch,
}

fn publish_proofs(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    mut proofs: Vec<Proof>,
    deadline: Instant,
) -> Result<(), String> {
    if proofs.is_empty() {
        return Ok(());
    }
    let transaction = state.cache_transaction_until(deadline)?;
    check_generation(state, snapshot)?;
    let assignments = assignments_until(state, snapshot, deadline)?;
    proofs.retain(|proof| {
        let backend = &proof.matched.backend;
        proof.matched.certificate.dns_san
            && assignments.get(&(backend.project.clone(), backend.role.clone()))
                == Some(&backend.port)
    });
    let proofs = proofs
        .into_iter()
        .map(|proof| {
            (
                (proof.pattern.clone(), proof.matched.backend.clone()),
                proof,
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    let claims = claim_path(state)
        .and_then(|path| {
            route_claims::update_existing_until(
                &path,
                Some(state.access_deadline(deadline)),
                |claims| {
                    claims.retain_registrations(&assignments);
                    for proof in &proofs {
                        claims.add(&proof.pattern, &proof.matched.backend.project);
                    }
                },
            )
        })
        .inspect_err(|_| fail(state, Failure::ClaimStateUnavailable))?;
    let saturated = !claims.saturated_workloads.is_empty();
    let pending = proofs
        .into_iter()
        .filter(|proof| {
            !saturated
                && claims.routes.get(&proof.pattern).is_some_and(|owners| {
                    owners.len() == 1 && owners.contains(&proof.matched.backend.project)
                })
        })
        .map(|proof| PendingRoute {
            hostname: proof.pattern,
            matched: proof.matched,
            declaration_generation: Some(snapshot.generation),
            observed: None,
        })
        .collect::<Vec<_>>();
    publish_claims(state, snapshot, claims, assignments);
    drop(transaction);
    if saturated {
        return Err(
            "ownership_claim_capacity_exhausted; registrations must release unrecorded claims"
                .into(),
        );
    }
    if !pending.is_empty() {
        for result in install_active_routes_until(state, pending, deadline)? {
            let pending = result?;
            clear_route_failure(state, &pending.hostname);
            state.successful_discoveries.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

pub(super) fn selected_pattern(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    hostname: &str,
) -> Result<Option<String>, String> {
    let discovery = state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(error) = discovery.error {
        return Err(format!("certificate_discovery blocked: {}", error.label()));
    }
    if !discovery.initialized || discovery.generation != snapshot.generation {
        return Ok(None);
    }
    let Some((pattern, owners)) = discovery.claims.matching(hostname) else {
        return Ok(None);
    };
    if owners.len() > 1 {
        return if pattern == hostname {
            Err(format!("ownership conflict for {hostname}"))
        } else {
            Ok(None)
        };
    }
    if pattern != hostname && !discovery.reconciled {
        return Ok(None);
    }
    Ok(Some(pattern.to_string()))
}

pub(super) fn resolve(
    hostname: &str,
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    deadline: Instant,
) -> Result<Backend, String> {
    let candidates = synchronise(state, snapshot, deadline)?;
    {
        let discovery = state
            .certificate_discovery
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = discovery.error {
            return Err(format!("certificate_discovery blocked: {}", error.label()));
        }
    }
    {
        let mut negative = state
            .negative
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        negative.retain(|_, expires| *expires > Instant::now());
        if negative.contains_key(hostname) {
            return Err(format!(
                "certificate discovery recently failed for {hostname}"
            ));
        }
    }
    let result = state.discover_once_until(hostname, deadline, |deadline| {
        let exact = state
            .certificate_discovery
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .claims
            .routes
            .get(hostname)
            .cloned();
        if let Some(owners) = exact {
            if owners.len() != 1 {
                return Err(format!("ownership conflict for {hostname}"));
            }
            let owner = owners.first().unwrap();
            let backend = candidates
                .iter()
                .find(|backend| &backend.project == owner)
                .ok_or_else(|| {
                    format!("exact ownership claim for {hostname} has no HTTPS registration")
                })?;
            let certificate = probe_declared_backend_until(hostname, backend, state, deadline)
                .inspect_err(|error| {
                    set_route_failure(
                        state,
                        hostname,
                        if error.starts_with("TCP connection failed") {
                            RouteFailure::BackendUnavailable
                        } else if error.contains("capacity") {
                            RouteFailure::CapacityUnavailable
                        } else {
                            RouteFailure::VerificationFailed
                        },
                    )
                })?;
            install_active_route_until(
                state,
                hostname,
                ProbeMatch {
                    backend: backend.clone(),
                    certificate,
                },
                Some(snapshot.generation),
                deadline,
            )?;
            clear_route_failure(state, hostname);
            return Ok(backend.clone());
        }
        let probed_candidates = candidates.clone();
        let scanned = probe_all_candidates_until(hostname, candidates, state, deadline);
        state.check_running_until(deadline)?;
        if !scanned.complete {
            return Err("certificate discovery could not check every registered Workload".into());
        }
        let proofs = scanned
            .matches
            .into_iter()
            .filter(|matched| matched.certificate.dns_san)
            .map(|matched| Proof {
                pattern: matched.certificate.route_pattern(hostname).to_string(),
                matched,
            })
            .collect::<Vec<_>>();
        let verified = proofs
            .iter()
            .map(|proof| (proof.pattern.clone(), proof.matched.backend.clone()))
            .collect::<BTreeSet<_>>();
        publish_proofs(state, snapshot, proofs, deadline)?;
        let pattern = {
            let discovery = state
                .certificate_discovery
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (pattern, owners) = discovery
                .claims
                .matching(hostname)
                .ok_or_else(|| format!("no trusted certificate owner for {hostname}"))?;
            if owners.len() != 1 {
                return Err(format!("ownership conflict for {pattern}"));
            }
            pattern.to_string()
        };
        let routes = state
            .routes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = routes
            .get(&pattern)
            .ok_or_else(|| format!("ownership claim for {hostname} is inactive"))?;
        if !verified.contains(&(pattern.clone(), active.backend.clone())) {
            return Err(format!(
                "ownership claim for {hostname} did not pass this verification"
            ));
        }
        let discovery = state
            .certificate_discovery
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if backends(&discovery.assignments) != probed_candidates {
            return Err(
                "registrations changed during certificate discovery; retry after reconciliation"
                    .into(),
            );
        }
        if !discovery.selects(hostname, &pattern, &active.backend, snapshot.generation)
            || !discovery.active(
                &pattern,
                active,
                snapshot.generation,
                current_unix_seconds(),
            )
        {
            return Err(format!("ownership claim for {hostname} is not verified"));
        }
        Ok(active.backend.clone())
    });
    if result.is_err() {
        cache_negative(state, hostname);
    }
    result
}

pub(super) fn reconcile(state: &ProxyState, snapshot: &PublicIngressSnapshot, deadline: Instant) {
    let candidates = match synchronise(state, snapshot, deadline) {
        Ok(candidates) => candidates,
        Err(_) => return,
    };
    if state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .error
        .is_some()
    {
        return;
    }
    let catalog_deadline = deadline
        .checked_sub(
            (deadline.saturating_duration_since(Instant::now()) / 4).min(DISCOVERY_TIMEOUT),
        )
        .unwrap_or(deadline);
    let mut proofs = Vec::new();
    let start = state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .catalog_cursor;
    for offset in 0..candidates.len() {
        if state.check_running_until(catalog_deadline).is_err() {
            break;
        }
        let index = (start + offset) % candidates.len();
        let backend = &candidates[index];
        let checked = state
            .certificate_discovery
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .checked
            .get(backend)
            .copied();
        let healthy = state
            .routes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .any(|active| {
                &active.backend == backend && active.certificate_is_valid_at(current_unix_seconds())
            });
        state
            .certificate_discovery
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .catalog_cursor = index + 1;
        if healthy && checked.is_some_and(|checked| checked.elapsed() < TLS_REVALIDATION_INTERVAL) {
            continue;
        }
        let probe_deadline = catalog_deadline.min(Instant::now() + PROBE_TIMEOUT);
        let Some(_background) = state.reconciliation_probes.acquire(probe_deadline) else {
            break;
        };
        let names = default_certificate_dns_names_until(state, backend, probe_deadline);
        if state.check_running_until(catalog_deadline).is_err() {
            break;
        }
        if names
            .as_ref()
            .is_err_and(|error| error.contains("capacity"))
        {
            continue;
        }
        let mut complete = true;
        let mut failure = names.as_ref().err().map(|error| {
            if error.starts_with("TCP connection failed") {
                "backend_unavailable"
            } else {
                "default_certificate_unavailable"
            }
        });
        if let Ok(names) = names {
            if names.is_empty() {
                failure = Some("no_dns_sans");
            }
            for pattern in names {
                if state.check_running_until(catalog_deadline).is_err()
                    || proofs.len() > route_claims::MAX_CLAIMS
                {
                    complete = false;
                    break;
                }
                let already_verified = state
                    .routes
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&pattern)
                    .is_some_and(|active| {
                        &active.backend == backend
                            && active.last_tls_check.elapsed() < TLS_REVALIDATION_INTERVAL
                            && active.certificate_is_valid_at(current_unix_seconds())
                    });
                if already_verified {
                    continue;
                }
                let proof_deadline = catalog_deadline.min(Instant::now() + PROBE_TIMEOUT);
                let proof = probe_declared_backend_until(&pattern, backend, state, proof_deadline);
                if state.check_running_until(catalog_deadline).is_err()
                    || proof
                        .as_ref()
                        .is_err_and(|error| error.contains("capacity"))
                {
                    complete = false;
                    break;
                }
                match proof {
                    Ok(certificate) => {
                        proofs.push(Proof {
                            pattern: certificate.route_pattern(&pattern).to_string(),
                            matched: ProbeMatch {
                                backend: backend.clone(),
                                certificate,
                            },
                        });
                    }
                    Err(_) => failure = Some("certificate_verification_failed"),
                }
            }
        }
        if complete {
            let mut discovery = state
                .certificate_discovery
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if discovery.generation == snapshot.generation
                && discovery
                    .assignments
                    .get(&(backend.project.clone(), backend.role.clone()))
                    == Some(&backend.port)
            {
                discovery.checked.insert(backend.clone(), Instant::now());
                if let Some(failure) = failure {
                    discovery.catalog_failures.insert(backend.clone(), failure);
                } else {
                    discovery.catalog_failures.remove(backend);
                }
            }
        }
    }
    if publish_proofs(state, snapshot, proofs, deadline).is_err() {
        eprintln!("event=certificate_discovery result=publication_failed");
    }
    let mut plan = snapshot.clone();
    {
        let mut discovery = state
            .certificate_discovery
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if discovery.generation != snapshot.generation {
            return;
        }
        discovery.reconciled = backends(&discovery.assignments)
            .iter()
            .all(|backend| discovery.checked.contains_key(backend));
        if discovery.error.is_some() {
            return;
        }
        plan.routes = discovery
            .claims
            .routes
            .iter()
            .filter(|(_, owners)| owners.len() == 1)
            .map(|(pattern, owners)| {
                (
                    pattern.clone(),
                    RouteDeclaration {
                        hostname: pattern.clone(),
                        workload: owners.first().unwrap().clone(),
                        role: "https".into(),
                        required: false,
                        relay_idle_timeout: Some(DEFAULT_RELAY_IDLE_TIMEOUT),
                    },
                )
            })
            .collect();
    }
    // Reuse the bounded public probe plan, not its operator declaration authority.
    reconcile_public_workloads(state, &plan, PROBE_TIMEOUT, deadline);
}

pub(super) fn summary(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    routes: &HashMap<String, ActiveRoute>,
    now: u64,
) -> RouteSummary {
    let discovery = state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let active = routes
        .iter()
        .filter(|(pattern, route)| discovery.active(pattern, route, snapshot.generation, now))
        .count();
    let reason = if let Some(error) = discovery.error {
        error.label()
    } else if discovery.generation != snapshot.generation {
        "discovery_pending"
    } else {
        discovery.readiness_reason(active, state.registry_valid.load(Ordering::Acquire))
    };
    RouteSummary {
        hosting_profile: "public",
        routing_policy: snapshot.routing_policy.label(),
        config_generation: snapshot.generation,
        declared_routes: 0,
        required_routes: 0,
        optional_routes: 0,
        claimed_routes: discovery.claims.routes.len(),
        discovery_workloads: discovery.observed_workloads,
        discovery_reconciled: Some(
            discovery.reconciled && discovery.generation == snapshot.generation,
        ),
        readiness_reason: reason,
        active_routes: active,
        degraded_routes: discovery.claims.routes.len().saturating_sub(active),
        ready: reason == "ready",
    }
}

pub(super) fn degraded_statuses(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    routes: &HashMap<String, ActiveRoute>,
    now: u64,
) -> Vec<DegradedRouteStatus> {
    let failures = state
        .route_failures
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let discovery = state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    discovery
        .claims
        .routes
        .iter()
        .filter(|(pattern, _)| {
            !routes
                .get(*pattern)
                .is_some_and(|active| discovery.active(pattern, active, snapshot.generation, now))
        })
        .take(MAX_ROUTE_DIAGNOSTICS)
        .map(|(pattern, owners)| DegradedRouteStatus {
            hostname: pattern.clone(),
            workload: owners.iter().cloned().collect::<Vec<_>>().join(","),
            role: "https".into(),
            required: false,
            reason: if owners.len() > 1 {
                "ownership_conflict"
            } else if let Some(error) = discovery.error {
                error.label()
            } else if routes
                .get(pattern)
                .is_some_and(|route| !route.certificate_is_valid_at(now))
            {
                "certificate_expired"
            } else {
                failures
                    .get(pattern)
                    .copied()
                    .map(RouteFailure::label)
                    .unwrap_or("awaiting_verification")
            },
        })
        .collect()
}

pub(super) fn certificate_statuses(
    state: &ProxyState,
    snapshot: &PublicIngressSnapshot,
    routes: &HashMap<String, ActiveRoute>,
    now: u64,
) -> (usize, Vec<DeclaredCertificateStatus>) {
    let discovery = state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut count = 0;
    let statuses = discovery
        .claims
        .routes
        .keys()
        .filter_map(|pattern| {
            let active = routes.get(pattern)?;
            if active.declaration_generation != Some(snapshot.generation)
                || !discovery.owns(pattern, &active.backend, snapshot.generation)
            {
                return None;
            }
            count += 1;
            (count <= MAX_ROUTE_DIAGNOSTICS).then(|| DeclaredCertificateStatus {
                hostname: pattern.clone(),
                workload: active.backend.project.clone(),
                role: "https".into(),
                required: false,
                not_after_unix_seconds: active.certificate.not_after_unix_seconds,
                expiry_state: active.certificate.expiry_state_at(now).label(),
            })
        })
        .collect();
    (count, statuses)
}

pub(super) fn workload_failures(state: &ProxyState) -> Vec<DiscoveryWorkloadStatus> {
    state
        .certificate_discovery
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .catalog_failures
        .iter()
        .take(route_claims::MAX_DISCOVERY_WORKLOADS)
        .map(|(backend, reason)| DiscoveryWorkloadStatus {
            workload: backend.project.clone(),
            role: backend.role.clone(),
            port: backend.port,
            reason,
        })
        .collect()
}

#[cfg(all(test, unix))]
#[path = "certificate_discovery_tests.rs"]
mod tests;
