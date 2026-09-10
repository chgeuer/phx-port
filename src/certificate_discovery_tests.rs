use super::*;
use crate::proxy::tests::{
    TestCertificate, TestTlsBackend, wildcard_routing::request, write_logical_registry,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::{TempDir, tempdir_in};

const WILDCARD: &str = "*.public.example.test";
const EXACT: &str = "specific.public.example.test";
const OTHER: &str = "arbitrary-947.public.example.test";

fn directory() -> TempDir {
    let root = std::env::var_os("PHX_PORT_TEST_TMPDIR")
        .map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    tempdir_in(root).unwrap()
}

fn restart(directory: &Path, connector: TlsConnector) -> Arc<ProxyState> {
    let profile = HostingProfile::load(Some(directory.join("ingress.toml"))).unwrap();
    assert_eq!(profile.name(), "public");
    assert_eq!(profile.public_snapshot().unwrap().routing_policy, RoutingPolicy::CertificateDiscovery);
    let paths = ProductionPaths {
        port_registry: directory.join("ports.toml"),
        route_cache: directory.join("routes.toml"),
        runtime_root: directory.join("runtime"),
    };
    paths.prepare_for_policy(RoutingPolicy::CertificateDiscovery).unwrap();
    let mut state = ProxyState::new_with_production_paths(profile, paths);
    state.probe_connector_override = Some(connector);
    Arc::new(state)
}

fn setup(
    directory: &Path, assignments: &[(&str, u16)], connector: TlsConnector,
) -> Arc<ProxyState> {
    write_logical_registry(directory, assignments);
    fs::write(directory.join("ingress.toml"),
        "[ingress]\nmode = \"public\"\nrouting_policy = \"certificate_discovery\"\n").unwrap();
    fs::set_permissions(directory.join("ingress.toml"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::create_dir(directory.join("runtime")).unwrap();
    fs::set_permissions(directory.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
    restart(directory, connector)
}

fn register(state: &ProxyState, id: &str, port: u16) {
    port_registry::update(&state.config, port_registry::RegistrySecurity::LogicalWorkload, |document| {
        document["ports"][id] = toml_edit::table();
        document["ports"][id]["https"] = toml_edit::value(i64::from(port));
        Ok(())
    }).unwrap();
}

fn unregister(state: &ProxyState, id: &str) {
    port_registry::update(&state.config, port_registry::RegistrySecurity::LogicalWorkload, |document| {
        document["ports"].as_table_mut().unwrap().remove(id);
        Ok(())
    }).unwrap();
}

fn reconcile(state: &ProxyState) {
    super::reconcile(
        state, &state.public_snapshot().unwrap(), Instant::now() + RECONCILIATION_PASS_TIMEOUT,
    );
}

#[test]
fn public_discovery_uses_exact_precedence_in_both_startup_orders() {
    for exact_first in [true, false] {
        let directory = directory();
        let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
        let exact_certificate = TestCertificate::for_hostname(EXACT);
        let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
        let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
        let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
        let (wildcard_id, exact_id) = if exact_first { ("z-wild", "a-exact") } else { ("a-wild", "z-exact") };
        let state = setup(directory.path(), &[(wildcard_id, wildcard.port()), (exact_id, exact.port())], connector.clone());
        reconcile(&state);

        assert_eq!(state.routes.read().unwrap().len(), 2);
        assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
        for hostname in [OTHER, "another.public.example.test"] {
            assert_eq!(request(&state, &connector, hostname).unwrap(), *b"wildcard");
        }
        assert!(state.conflicts.read().unwrap().is_empty());
        assert_eq!(state.certificate_discovery.read().unwrap().claims.routes.len(), 2);
        assert!(state.public_snapshot().unwrap().routes.is_empty());
    }
}

#[test]
fn a_later_exact_workload_overrides_a_running_wildcard() {
    let directory = directory();
    let wildcard_certificate = TestCertificate::for_hostname(WILDCARD);
    let exact_certificate = TestCertificate::for_hostname(EXACT);
    let wildcard = TestTlsBackend::start(&wildcard_certificate, b"wildcard");
    let exact = TestTlsBackend::start(&exact_certificate, b"exact!!!");
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
    let state = setup(directory.path(), &[("wild", wildcard.port())], connector.clone());
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
    let state = setup(directory.path(), &[("wild", wildcard.port()), ("exact", exact_port)], connector.clone());
    reconcile(&state);
    assert_eq!(request(&state, &connector, EXACT).unwrap(), *b"exact!!!");
    drop(exact);
    for _ in 0..3 {
        reconcile(&state);
    }
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    drop(state);

    let state = restart(directory.path(), connector.clone());
    assert!(state.routes.read().unwrap().is_empty(), "no persisted proof is an activation");
    reconcile(&state);
    assert!(request(&state, &connector, EXACT).is_err());
    assert_eq!(request(&state, &connector, OTHER).unwrap(), *b"wildcard");
    assert!(state.certificate_discovery.read().unwrap().claims.routes.contains_key(EXACT));

    let exact = TestTlsBackend::start_at(&exact_certificate, b"exact!!!", ([127, 0, 0, 1], exact_port).into());
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
    let claims = route_claims::load_until(&directory.path().join("route-claims.toml"), None).unwrap();
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
    let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate, &expired]);
    let state = setup(directory.path(), &[("wild", wildcard.port()), ("exact", exact.port())], connector.clone());
    reconcile(&state);
    exact.replace_certificate(&expired);
    state.routes.write().unwrap().get_mut(EXACT).unwrap().certificate.not_after_unix_seconds = current_unix_seconds();
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
        let contender_certificate = if pattern == EXACT { &exact_certificate } else { &wildcard_certificate };
        let contender = TestTlsBackend::start(contender_certificate, b"contendr");
        let connector = TestCertificate::connector_for(&[&wildcard_certificate, &exact_certificate]);
        let state = setup(directory.path(), &[("wild", wildcard.port()), ("exact", exact.port())], connector.clone());
        reconcile(&state);
        register(&state, "contender", contender.port());
        reconcile(&state);
        assert!(!state.routes.read().unwrap().contains_key(pattern));
        assert_eq!(state.certificate_discovery.read().unwrap().claims.routes[pattern].len(), 2);
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
        assert_eq!(state.certificate_discovery.read().unwrap().claims.routes[pattern].len(), 2);
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
    let state = setup(directory.path(), &[("wild", workload.port())], certificate.connector());
    reconcile(&state);
    for hostname in ["public.example.test", "deep.foo.public.example.test", "badpublic.example.test",
        "foo.public.example.test.evil", WILDCARD] {
        assert!(request(&state, &certificate.connector(), hostname).is_err(), "{hostname}");
    }
    assert_eq!(state.certificate_discovery.read().unwrap().claims.routes.len(), 1);
}

#[test]
fn untrusted_certificates_never_create_public_claims_or_activations() {
    let directory = directory();
    let certificate = TestCertificate::for_hostname(WILDCARD);
    let workload = TestTlsBackend::start(&certificate, b"wildcard");
    let state = setup(directory.path(), &[("wild", workload.port())], TestCertificate::unrelated_connector(WILDCARD));
    reconcile(&state);
    assert!(state.certificate_discovery.read().unwrap().claims.routes.is_empty());
    assert!(request(&state, &certificate.connector(), OTHER).is_err());
    assert!(state.routes.read().unwrap().is_empty());
}

#[test]
fn cached_public_claims_do_not_bypass_trust_on_restart() {
    let directory = directory();
    let certificate = TestCertificate::for_hostname(WILDCARD);
    let workload = TestTlsBackend::start(&certificate, b"wildcard");
    let state = setup(directory.path(), &[("wild", workload.port())], certificate.connector());
    reconcile(&state);
    assert_eq!(state.routes.read().unwrap().len(), 1);
    drop(state);
    let state = restart(directory.path(), TestCertificate::unrelated_connector(WILDCARD));
    reconcile(&state);
    assert_eq!(state.certificate_discovery.read().unwrap().claims.routes.len(), 1);
    assert!(state.routes.read().unwrap().is_empty());
    assert!(request(&state, &certificate.connector(), OTHER).is_err());
}
