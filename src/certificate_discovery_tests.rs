use super::*;
use crate::proxy::tests::{
    TestCertificate, TestTlsBackend,
    wildcard_routing::{delay_first_handshake, request},
    write_logical_registry,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::{TempDir, tempdir_in};

const WILDCARD: &str = "*.public.example.test";
const EXACT: &str = "specific.public.example.test";
const OTHER: &str = "arbitrary-947.public.example.test";

fn directory() -> TempDir {
    let root = std::env::var_os("PHX_PORT_TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    tempdir_in(root.canonicalize().unwrap()).unwrap()
}

fn restart(directory: &Path, connector: TlsConnector) -> Arc<ProxyState> {
    let profile = HostingProfile::load(Some(directory.join("ingress.toml"))).unwrap();
    assert_eq!(profile.name(), "public");
    assert_eq!(
        profile.public_snapshot().unwrap().routing_policy,
        RoutingPolicy::CertificateDiscovery
    );
    let paths = ProductionPaths {
        port_registry: directory.join("ports.toml"),
        route_cache: directory.join("routes.toml"),
        runtime_root: directory.join("runtime"),
    };
    paths
        .prepare_for_policy(RoutingPolicy::CertificateDiscovery)
        .unwrap();
    let mut state = ProxyState::new_with_production_paths(profile, paths);
    state.probe_connector_override = Some(connector);
    Arc::new(state)
}

fn setup(
    directory: &Path,
    assignments: &[(&str, u16)],
    connector: TlsConnector,
) -> Arc<ProxyState> {
    write_logical_registry(directory, assignments);
    fs::write(
        directory.join("ingress.toml"),
        "[ingress]\nmode = \"public\"\nrouting_policy = \"certificate_discovery\"\n",
    )
    .unwrap();
    fs::set_permissions(
        directory.join("ingress.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::create_dir(directory.join("runtime")).unwrap();
    fs::set_permissions(directory.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
    restart(directory, connector)
}

fn register(state: &ProxyState, id: &str, port: u16) {
    port_registry::update(
        &state.config,
        port_registry::RegistrySecurity::LogicalWorkload,
        |document| {
            document["ports"][id] = toml_edit::table();
            document["ports"][id]["https"] = toml_edit::value(i64::from(port));
            Ok(())
        },
    )
    .unwrap();
}

fn unregister(state: &ProxyState, id: &str) {
    port_registry::update(
        &state.config,
        port_registry::RegistrySecurity::LogicalWorkload,
        |document| {
            document["ports"].as_table_mut().unwrap().remove(id);
            Ok(())
        },
    )
    .unwrap();
}

fn reconcile(state: &ProxyState) {
    crate::proxy::reconcile_workloads_until(state, Instant::now() + RECONCILIATION_PASS_TIMEOUT);
}

fn reconcile_catalogues(state: &ProxyState) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        crate::proxy::reconcile_workloads_until(
            state,
            deadline.min(Instant::now() + RECONCILIATION_PASS_TIMEOUT),
        );
        if state.certificate_discovery.read().unwrap().reconciled {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "certificate catalogues remained incomplete"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn damaged_or_missing_live_claims_block_routing_until_authority_is_restored() {
    let directory = directory();
    let certificate = TestCertificate::for_hostname(WILDCARD);
    let workload = TestTlsBackend::start(&certificate, b"wildcard");
    let connector = certificate.connector();
    let state = setup(
        directory.path(),
        &[("wild", workload.port())],
        connector.clone(),
    );
    reconcile(&state);
    let path = directory.path().join("route-claims.toml");
    let original = fs::read(&path).unwrap();

    for fault in ["corrupt", "missing", "unsafe_mode"] {
        match fault {
            "corrupt" => fs::write(&path, "not valid [toml").unwrap(),
            "missing" => fs::remove_file(&path).unwrap(),
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
        }
        reconcile(&state);
        assert_eq!(
            state.certificate_discovery.read().unwrap().error,
            Some(Failure::ClaimStateUnavailable),
            "{fault}"
        );
        assert!(request(&state, &connector, OTHER).is_err(), "{fault}");

        fs::write(&path, &original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        reconcile(&state);
        assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    }
}

#[test]
fn initial_same_specificity_owners_never_choose_an_arbitrary_public_winner() {
    for pattern in [EXACT, WILDCARD] {
        let directory = directory();
        let certificate = TestCertificate::for_hostname(pattern);
        let first = TestTlsBackend::start(&certificate, b"first!!!");
        let second = TestTlsBackend::start(&certificate, b"second!!");
        let connector = certificate.connector();
        let state = setup(
            directory.path(),
            &[("a-first", first.port()), ("z-second", second.port())],
            connector.clone(),
        );
        reconcile(&state);
        assert!(!state.routes.read().unwrap().contains_key(pattern));
        assert_eq!(
            state.certificate_discovery.read().unwrap().claims.routes[pattern].len(),
            2
        );
        let hostname = if pattern == EXACT { EXACT } else { OTHER };
        assert!(request(&state, &connector, hostname).is_err());
    }
}

#[test]
fn public_discovery_uses_exact_precedence_in_both_startup_orders() {
    for (exact_first, eager) in [(true, true), (false, true), (true, false), (false, false)] {
        let directory = directory();
        let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
        let exact_certificate = TestCertificate::for_hostname(EXACT);
        let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
        let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
        let connector =
            TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
        let (wildcard_id, exact_id) = if exact_first {
            ("z-wild", "a-exact")
        } else {
            ("a-wild", "z-exact")
        };
        let state = setup(
            directory.path(),
            &[(wildcard_id, wildcard.port()), (exact_id, exact.port())],
            connector.clone(),
        );
        if eager {
            reconcile_catalogues(&state);
        } else {
            assert!(state.routes.read().unwrap().is_empty());
            delay_first_handshake(
                &exact,
                Some(EXACT),
                DISCOVERY_TIMEOUT + Duration::from_millis(100),
            );
        }

        for (hostname, id, port) in [
            (EXACT, exact_id, exact.port()),
            (OTHER, wildcard_id, wildcard.port()),
            ("another.public.example.test", wildcard_id, wildcard.port()),
        ] {
            let selected =
                resolve_backend_until(hostname, &state, Instant::now() + Duration::from_secs(2))
                    .unwrap();
            assert_eq!(
                selected.project, id,
                "exact_first={exact_first}, eager={eager}"
            );
            assert_eq!(selected.role, "https");
            assert_eq!(selected.port, port);
        }
        if !eager {
            reconcile_catalogues(&state);
        }
        assert_eq!(state.routes.read().unwrap().len(), 2);
        assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
        for hostname in [OTHER, "another.public.example.test"] {
            assert_eq!(request(&state, &connector, hostname).unwrap(), *b"wildcard");
        }
        assert!(state.conflicts.read().unwrap().is_empty());
        assert_eq!(
            state
                .certificate_discovery
                .read()
                .unwrap()
                .claims
                .routes
                .len(),
            2
        );
        assert!(state.public_snapshot().unwrap().routes.is_empty());
    }
}

#[test]
fn cold_exact_proof_timeout_never_routes_to_the_faster_wildcard() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("a-wild", wildcard.port()), ("z-exact", exact.port())],
        connector.clone(),
    );
    delay_first_handshake(
        &exact,
        Some(EXACT),
        DISCOVERY_TIMEOUT + Duration::from_millis(100),
    );

    let error = request(&state, &connector, EXACT).unwrap_err();
    assert!(error.contains("route selection timed out"), "{error}");
    assert_eq!(state.rejected_routing_timeout.load(Ordering::Acquire), 1);
    assert_eq!(state.relayed_connections.load(Ordering::Acquire), 0);
    assert_eq!(state.handoff_attempts.load(Ordering::Acquire), 0);
    assert_eq!(state.admission.snapshot().global.in_use, 0);
    assert!(state.routes.read().unwrap().is_empty());
    assert!(
        state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .is_empty()
    );
}

#[test]
fn a_registration_added_during_a_cold_scan_cannot_be_ignored_by_a_wildcard() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port())],
        connector.clone(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let permits = (0..MAX_PROBES)
        .map(|_| state.probes.acquire(deadline).unwrap())
        .collect::<Vec<_>>();
    let worker_state = Arc::clone(&state);
    let worker = thread::spawn(move || resolve_backend_until(EXACT, &worker_state, deadline));
    while state.waiting_clients.load(Ordering::Acquire) == 0 {
        assert!(Instant::now() < deadline, "cold discovery did not start");
        thread::sleep(Duration::from_millis(1));
    }
    register(&state, "exact", exact.port());
    drop(permits);
    assert!(
        worker
            .join()
            .unwrap()
            .unwrap_err()
            .contains("registrations changed")
    );
    reconcile(&state);
    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
}

#[test]
fn pending_catalogue_and_probe_exhaustion_never_serve_a_cached_wildcard_for_an_exact_candidate() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port())],
        connector.clone(),
    );
    reconcile(&state);
    let deadline = Instant::now() + Duration::from_secs(2);
    let permits = (0..MAX_PROBES)
        .map(|_| state.probes.acquire(deadline).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    register(&state, "exact", exact.port());
    synchronise(&state, &state.public_snapshot().unwrap(), deadline).unwrap();
    assert!(request(&state, &connector, EXACT).is_err());
    assert!(
        !state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .contains_key(EXACT)
    );
    drop(permits);
    reconcile(&state);
    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
}

#[test]
fn a_later_exact_workload_overrides_a_running_wildcard() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port())],
        connector.clone(),
    );
    reconcile(&state);
    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"wildcard");

    register(&state, "exact", exact.port());
    reconcile(&state);

    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
}

#[test]
fn exact_claim_blocks_wildcard_across_outage_ingress_restart_and_service_return() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let exact_port = exact.port();
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port()), ("exact", exact_port)],
        connector.clone(),
    );
    reconcile(&state);
    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
    drop(exact);
    assert!(
        request(&state, &connector, EXACT).is_err(),
        "a cached-connect failure must not use the wildcard"
    );
    for _ in 0..3 {
        reconcile(&state);
    }
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    drop(state);

    let state = restart(directory.path(), connector.clone());
    assert!(
        state.routes.read().unwrap().is_empty(),
        "no persisted proof is an activation"
    );
    reconcile(&state);
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    assert!(
        state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .contains_key(EXACT)
    );

    let exact = TestTlsBackend::start_at(
        &exact_certificate,
        b"exact!!!",
        ([127, 0, 0, 1], exact_port).into(),
    );
    reconcile(&state);
    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
    drop(exact);
    for _ in 0..3 {
        reconcile(&state);
    }
    assert!(request(&state, &connector, EXACT).is_err());

    unregister(&state, "exact");
    reconcile(&state);
    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"wildcard");
    let claims =
        route_claims::load_until(&directory.path().join("route-claims.toml"), None).unwrap();
    assert!(!claims.routes.contains_key(EXACT));
    assert_eq!(claims.routes.len(), 1);
}

#[test]
fn expired_exact_certificate_keeps_its_durable_assignment() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let expired = TestCertificate::for_hostname_valid_for(EXACT, Duration::ZERO);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector =
        TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate, &expired]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port()), ("exact", exact.port())],
        connector.clone(),
    );
    reconcile(&state);
    exact.replace_certificate(&expired);
    state
        .routes
        .write()
        .unwrap()
        .get_mut(EXACT)
        .unwrap()
        .certificate
        .not_after_unix_seconds = current_unix_seconds();
    reconcile(&state);
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    drop(state);
    let state = restart(directory.path(), connector.clone());
    reconcile(&state);
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
}

#[test]
fn same_specificity_conflicts_withdraw_the_incumbent_but_not_other_routes() {
    for pattern in [EXACT, WILDCARD] {
        let directory = directory();
        let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
        let exact_certificate = TestCertificate::for_hostname(EXACT);
        let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
        let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
        let contender_certificate = if pattern == EXACT {
            &exact_certificate
        } else {
            &wildcard_certificate
        };
        let contender = TestTlsBackend::start(contender_certificate, b"contendr");
        let connector =
            TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
        let state = setup(
            directory.path(),
            &[("wild", wildcard.port()), ("exact", exact.port())],
            connector.clone(),
        );
        reconcile(&state);
        register(&state, "contender", contender.port());
        reconcile(&state);
        assert!(!state.routes.read().unwrap().contains_key(pattern));
        assert_eq!(
            state.certificate_discovery.read().unwrap().claims.routes[pattern].len(),
            2
        );
        if pattern == EXACT {
            assert!(request(&state, &connector, EXACT).is_err());
            assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
        } else {
            assert!(request(&state, &connector, OTHER).is_err());
            assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
        }
        drop(state);
        let state = restart(directory.path(), connector.clone());
        reconcile(&state);
        assert_eq!(
            state.certificate_discovery.read().unwrap().claims.routes[pattern].len(),
            2
        );
        unregister(&state, "contender");
        reconcile(&state);
        assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
        assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    }
}

#[test]
fn public_discovery_rejects_apex_deep_suffix_and_literal_wildcard_sni() {
    let directory = directory();
    let certificate = TestCertificate::for_hostname(WILDCARD);
    let workload = TestTlsBackend::start(&certificate, b"wildcard");
    let state = setup(
        directory.path(),
        &[("wild", workload.port())],
        certificate.connector(),
    );
    reconcile(&state);
    for hostname in [
        "public.example.test",
        "deep.foo.public.example.test",
        "badpublic.example.test",
        "foo.public.example.test.evil",
        WILDCARD,
    ] {
        assert!(
            !matches!(current_active_route(&state, hostname), Ok(Some(_))),
            "invalid name was routed: {hostname}"
        );
        assert!(
            request(&state, &certificate.connector(), hostname).is_err(),
            "{hostname}"
        );
    }
    assert_eq!(
        state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .len(),
        1
    );
}

#[test]
fn untrusted_certificates_never_create_public_claims_or_activations() {
    let directory = directory();
    let certificate = TestCertificate::for_hostname(WILDCARD);
    let workload = TestTlsBackend::start(&certificate, b"wildcard");
    let state = setup(
        directory.path(),
        &[("wild", workload.port())],
        TestCertificate::unrelated_connector(WILDCARD),
    );
    reconcile(&state);
    assert!(
        state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .is_empty()
    );
    assert!(request(&state, &certificate.connector(), OTHER).is_err());
    assert!(state.routes.read().unwrap().is_empty());
}

#[test]
fn cached_public_claims_do_not_bypass_trust_on_restart() {
    let directory = directory();
    let certificate = TestCertificate::for_hostname(WILDCARD);
    let workload = TestTlsBackend::start(&certificate, b"wildcard");
    let state = setup(
        directory.path(),
        &[("wild", workload.port())],
        certificate.connector(),
    );
    reconcile(&state);
    assert_eq!(state.routes.read().unwrap().len(), 1);
    drop(state);
    let state = restart(
        directory.path(),
        TestCertificate::unrelated_connector(WILDCARD),
    );
    reconcile(&state);
    assert_eq!(
        state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .len(),
        1
    );
    assert!(state.routes.read().unwrap().is_empty());
    assert!(request(&state, &certificate.connector(), OTHER).is_err());
}

#[test]
fn status_readiness_and_metrics_report_public_discovery_without_dynamic_metric_labels() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port()), ("exact", exact.port())],
        connector.clone(),
    );
    let shutdown = IngressShutdown::new(Duration::from_secs(1));
    let status = || {
        serde_json::from_str::<serde_json::Value>(&render_control_response(
            &state,
            &shutdown,
            "STATUS JSON",
        ))
        .unwrap()
    };
    assert_eq!(status()["readiness_reason"], "discovery_pending");
    reconcile(&state);
    let current = status();
    assert_eq!(current["hosting_profile"], "public");
    assert_eq!(current["routing_policy"], "certificate_discovery");
    assert_eq!(current["declared_routes"], 0);
    assert_eq!(current["claimed_routes"], 2);
    assert_eq!(current["active_routes"], 2);
    assert_eq!(current["discovery_workloads"], 2);
    assert_eq!(current["discovery_reconciled"], true);
    assert_eq!(current["ready"], true);
    assert_eq!(current["certificate_route_count"], 2);
    let metrics = render_prometheus_metrics(&state, &shutdown);
    assert!(
        metrics.contains("hosting_profile=\"public\",routing_policy=\"certificate_discovery\"")
    );
    assert!(metrics.contains("phx_port_routes{state=\"claimed\"} 2"));
    assert!(metrics.contains("phx_port_discovery_certificate_not_after_min_seconds "));
    assert!(!metrics.contains("hostname="), "{metrics}");
    let flat = render_control_response(&state, &shutdown, "STATUS");
    assert!(flat.contains("routing_policy=certificate_discovery"));
    assert!(flat.contains("claimed_routes=2"));

    drop(exact);
    for _ in 0..3 {
        reconcile(&state);
    }
    let current = status();
    assert_eq!(current["active_routes"], 1);
    assert_eq!(current["degraded_route_count"], 1);
    assert_eq!(current["degraded_routes"][0]["hostname"], EXACT);
    assert_eq!(
        current["degraded_routes"][0]["reason"],
        "backend_unavailable"
    );
    assert_eq!(
        current["ready"], true,
        "one unrelated inactive claim must not stop a healthy route"
    );
    let routes = render_control_response(&state, &shutdown, "ROUTES");
    assert!(routes.contains(&format!("active\t{WILDCARD}")));
    assert!(routes.contains(&format!(
        "inactive\t{EXACT}\texact\thttps\tclaim\tbackend_unavailable"
    )));
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
}

#[test]
fn production_default_wildcard_hint_cannot_be_proved_by_an_exact_only_sni_leaf() {
    #[derive(Debug)]
    struct Selection {
        default: Arc<dyn rustls::server::ResolvesServerCert>,
        named: Arc<dyn rustls::server::ResolvesServerCert>,
    }
    impl rustls::server::ResolvesServerCert for Selection {
        fn resolve(
            &self,
            hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            if hello.server_name().is_none() {
                self.default.resolve(hello)
            } else {
                self.named.resolve(hello)
            }
        }
    }
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let representative_certificate = TestCertificate::for_hostname("a.public.example.test");
    let workload = TestTlsBackend::start(&wildcard_certificate, b"exact!!!");
    *workload.tls_config.write().unwrap() = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Selection {
                default: wildcard_certificate.server_config().cert_resolver.clone(),
                named: representative_certificate
                    .server_config()
                    .cert_resolver
                    .clone(),
            })),
    );
    let connector =
        TestCertificate::connector_for(&[&wildcard_certificate, &representative_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", workload.port())],
        connector.clone(),
    );
    reconcile(&state);
    assert!(
        state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .is_empty()
    );
    assert!(request(&state, &connector, OTHER).is_err());
    assert_eq!(
        request(&state, &connector, "a.public.example.test").unwrap(),
        *b"exact!!!"
    );
    assert!(
        !state
            .certificate_discovery
            .read()
            .unwrap()
            .claims
            .routes
            .contains_key(WILDCARD)
    );
}

#[test]
fn registry_overflow_blocks_instead_of_probing_an_arbitrary_subset() {
    let directory = directory();
    let certificate = TestCertificate::for_hostname(WILDCARD);
    let workload = TestTlsBackend::start(&certificate, b"wildcard");
    let state = setup(
        directory.path(),
        &[("wild", workload.port())],
        certificate.connector(),
    );
    reconcile(&state);
    let listeners = (0..route_claims::MAX_DISCOVERY_WORKLOADS)
        .map(|index| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            register(
                &state,
                &format!("extra-{index}"),
                listener.local_addr().unwrap().port(),
            );
            listener
        })
        .collect::<Vec<_>>();
    let accepted = workload.accepted();
    reconcile(&state);
    assert_eq!(workload.accepted(), accepted);
    assert!(request(&state, &certificate.connector(), OTHER).is_err());
    let status = render_control_response(
        &state,
        &IngressShutdown::new(Duration::from_secs(1)),
        "STATUS",
    );
    assert!(
        status.contains("readiness_reason=discovery_workload_capacity_exhausted"),
        "{status}"
    );
    assert!(status.contains("discovery_workloads=33"), "{status}");
    drop(listeners);
}

#[test]
fn claim_exhaustion_blocks_wildcards_durably_without_evicting_an_exact_assignment() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let unrelated = TestCertificate::for_hostname("unused.example.test");
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let full = TestTlsBackend::start(&unrelated, b"unused!!");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port()), ("full", full.port())],
        connector.clone(),
    );
    reconcile(&state);
    route_claims::update_until(
        &directory.path().join("route-claims.toml"),
        None,
        |claims| {
            for index in 0..route_claims::MAX_CLAIMS - 1 {
                claims.add(&format!("old-{index}.example.test"), "full");
            }
        },
    )
    .unwrap();
    register(&state, "overflow", exact.port());
    reconcile(&state);
    let claims =
        route_claims::load_until(&directory.path().join("route-claims.toml"), None).unwrap();
    assert_eq!(claims.routes.len(), route_claims::MAX_CLAIMS);
    assert!(claims.routes.contains_key("old-0.example.test"));
    assert!(claims.saturated_workloads.contains("overflow"));
    assert!(request(&state, &connector, EXACT).is_err());
    assert!(request(&state, &connector, OTHER).is_err());
    drop(state);
    let state = restart(directory.path(), connector.clone());
    reconcile(&state);
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(
        state.certificate_discovery.read().unwrap().error,
        Some(Failure::ClaimCapacity)
    );
}

#[test]
fn policy_reload_preserves_claims_and_rejects_stale_discovery_results() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(
        directory.path(),
        &[("wild", wildcard.port()), ("exact", exact.port())],
        connector.clone(),
    );
    reconcile(&state);
    let old = state.public_snapshot().unwrap();
    let old_backend = state.routes.read().unwrap()[EXACT].backend.clone();
    let old_proof = probe_backend(EXACT, &old_backend, Some(&connector)).unwrap();
    drop(exact);
    fs::write(directory.path().join("ingress.toml"), format!(
        "[ingress]\nmode = \"public\"\n[ingress.hosts.\"{OTHER}\"]\nworkload = \"wild\"\nrole = \"https\"\n",
    )).unwrap();
    assert_eq!(
        reload_public_profile(&state),
        ConfigReloadOutcome::Accepted(2)
    );
    assert_eq!(
        state.public_snapshot().unwrap().routing_policy,
        RoutingPolicy::Declared
    );
    let claims_before = fs::read(directory.path().join("route-claims.toml")).unwrap();
    assert!(
        publish_proofs(
            &state,
            &old,
            vec![Proof {
                pattern: EXACT.into(),
                matched: ProbeMatch {
                    backend: old_backend,
                    certificate: old_proof
                },
            }],
            Instant::now() + DISCOVERY_TIMEOUT
        )
        .is_err()
    );
    assert_eq!(
        fs::read(directory.path().join("route-claims.toml")).unwrap(),
        claims_before
    );
    reconcile(&state);
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    assert!(
        request(&state, &connector, EXACT)
            .unwrap_err()
            .contains("no Route Declaration")
    );

    fs::write(
        directory.path().join("ingress.toml"),
        "[ingress]\nmode = \"public\"\nrouting_policy = \"certificate_discovery\"\n",
    )
    .unwrap();
    let claims_path = directory.path().join("route-claims.toml");
    for missing in [false, true] {
        if missing {
            fs::remove_file(&claims_path).unwrap();
        } else {
            fs::write(&claims_path, "").unwrap();
        }
        assert_eq!(
            reload_public_profile(&state),
            ConfigReloadOutcome::Rejected(3)
        );
        assert_eq!(
            state.public_snapshot().unwrap().routing_policy,
            RoutingPolicy::Declared
        );
        assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
        fs::write(&claims_path, &claims_before).unwrap();
        fs::set_permissions(&claims_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(
        reload_public_profile(&state),
        ConfigReloadOutcome::Accepted(3)
    );
    reconcile(&state);
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
}
