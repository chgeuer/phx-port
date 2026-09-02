use crate::{
    activated_listener,
    ingress_config::{HostingProfile, PublicIngressSnapshot},
    ingress_limits::DaemonConfig,
    port_registry,
    production_paths::ProductionPaths,
    proxy,
};
use native_tls::TlsConnector;
use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;

const INGRESS_CONFIG_ENV: &str = "PHX_PORT_INGRESS_CONFIG";
const MAX_REPORTED_ROUTE_FAILURES: usize = 16;
const MAX_FAILURE_DETAIL_LENGTH: usize = 256;

pub const USAGE: &str = "\
Usage: phx-port proxy preflight --file PATH [--listen ADDRESS]... [CAPACITY OPTIONS]
       PHX_PORT_INGRESS_CONFIG=PATH phx-port proxy preflight [--listen ADDRESS]...

Pass the same --listen and capacity options used by the daemon. Preflight never
auto-detects production, accepts public connections, or changes configured limits.";

#[derive(Clone, Debug)]
struct RouteTarget {
    hostname: String,
    workload: String,
    role: String,
    required: bool,
    port: u16,
}

#[derive(Clone, Debug)]
struct RouteIssue {
    hostname: String,
    workload: String,
    role: String,
    detail: String,
}

#[derive(Default)]
struct Report {
    checks: Vec<Check>,
}

struct Check {
    status: Status,
    name: &'static str,
    detail: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

impl Report {
    fn push(&mut self, status: Status, name: &'static str, detail: impl Into<String>) {
        self.checks.push(Check {
            status,
            name,
            detail: detail.into(),
        });
    }

    fn pass(&mut self, name: &'static str, detail: impl Into<String>) {
        self.push(Status::Pass, name, detail);
    }

    fn warn(&mut self, name: &'static str, detail: impl Into<String>) {
        self.push(Status::Warn, name, detail);
    }

    fn fail(&mut self, name: &'static str, detail: impl Into<String>) {
        self.push(Status::Fail, name, detail);
    }

    fn finish(self) -> Result<(), String> {
        let failures = self
            .checks
            .iter()
            .filter(|check| check.status == Status::Fail)
            .count();
        let warnings = self
            .checks
            .iter()
            .filter(|check| check.status == Status::Warn)
            .count();
        let mut output = String::new();
        for check in &self.checks {
            output.push_str(&format!(
                "{} {}: {}\n",
                check.status.label(),
                check.name,
                check.detail
            ));
        }
        if failures == 0 {
            output.push_str(&format!(
                "Preflight passed: {} checks, {warnings} warning(s); no public connections were accepted.\n",
                self.checks.len()
            ));
        } else {
            output.push_str(&format!(
                "Preflight failed: {failures} blocking check(s), {warnings} warning(s); no public connections were accepted.\n"
            ));
        }
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(output.as_bytes())
            .map_err(|error| format!("cannot write preflight report: {error}"))?;
        stdout
            .flush()
            .map_err(|error| format!("cannot flush preflight report: {error}"))?;
        if failures == 0 {
            Ok(())
        } else {
            Err(format!("{failures} blocking preflight check(s) failed"))
        }
    }
}

pub fn parse(args: &[String]) -> Result<DaemonConfig, String> {
    let normalized = args
        .iter()
        .map(|argument| {
            if argument == "--file" {
                "--ingress-config".to_string()
            } else {
                argument.clone()
            }
        })
        .collect::<Vec<_>>();
    let config = DaemonConfig::parse(&normalized)?;
    if config.ingress_config.is_none() && env::var_os(INGRESS_CONFIG_ENV).is_none() {
        return Err(format!(
            "proxy preflight requires --file PATH or {INGRESS_CONFIG_ENV}; production is never auto-detected"
        ));
    }
    if config.run_as.is_some() {
        return Err(
            "proxy preflight does not drop privilege; run it as the configured service identity"
                .to_string(),
        );
    }
    Ok(config)
}

pub fn run(config: DaemonConfig) -> Result<(), String> {
    let DaemonConfig {
        listen_addresses,
        listeners_explicit: _,
        ingress_config,
        run_as: _,
        limits,
        task_budget,
    } = config;
    let mut report = Report::default();

    check_execution_identity(&mut report);

    let parsed_listeners = listen_addresses
        .iter()
        .map(|address| {
            address
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid ingress listener address {address:?}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>();
    let loopback_only = parsed_listeners
        .as_ref()
        .is_ok_and(|listeners| listeners.iter().all(|address| address.ip().is_loopback()));

    let mut ingress_configuration_valid = false;
    let snapshot = match HostingProfile::load_for_daemon(ingress_config, loopback_only) {
        Ok(profile) => match profile.public_snapshot() {
            Some(snapshot) => {
                match profile.validate_daemon_listeners(&listen_addresses, false) {
                    Ok(()) => {
                        ingress_configuration_valid = true;
                        report.pass(
                            "ingress configuration",
                            format!(
                                "{} contains {} exact Route Declaration(s) matching {} listener(s)",
                                snapshot.ingress_config.display(),
                                snapshot.routes.len(),
                                listen_addresses.len()
                            ),
                        );
                    }
                    Err(error) => report.fail("ingress configuration", error),
                }
                Some(snapshot)
            }
            None => {
                report.fail(
                    "ingress configuration",
                    "preflight requires an explicit mode = \"public\" ingress config",
                );
                None
            }
        },
        Err(error) => {
            report.fail("ingress configuration", error);
            None
        }
    };

    let mut production_paths_valid = false;
    let paths = match ProductionPaths::from_environment() {
        Ok(paths) => {
            let result = (|| {
                if let Some(snapshot) = &snapshot {
                    paths.validate_intent_separation(&snapshot.ingress_config)?;
                }
                paths.validate()
            })();
            match result {
                Ok(()) => {
                    production_paths_valid = true;
                    report.pass(
                        "production paths",
                        format!(
                            "Port Registry {}, derived routes {}, and runtime root {} are secure",
                            paths.port_registry.display(),
                            paths.route_cache.display(),
                            paths.runtime_root.display()
                        ),
                    );
                }
                Err(error) => report.fail("production paths", error),
            }
            Some(paths)
        }
        Err(error) => {
            report.fail("production paths", error);
            None
        }
    };

    if let Some(paths) = &paths
        && production_paths_valid
    {
        match paths.validate_sandbox_access() {
            Ok(()) => report.pass(
                "sandbox access",
                "service identity can create and remove bounded probes in state and runtime roots",
            ),
            Err(error) => report.fail("sandbox access", error),
        }
        check_control_authorization(&mut report, paths, loopback_only);
    } else if paths.is_some() {
        report.fail(
            "sandbox access",
            "not attempted because production path security validation failed",
        );
        report.fail(
            "control authorization",
            "cannot validate local control ownership until production path security passes",
        );
    } else {
        report.fail(
            "sandbox access",
            "cannot test state and runtime access until production paths resolve",
        );
        report.fail(
            "control authorization",
            "cannot validate local control ownership until the runtime root resolves",
        );
    }

    let metrics_enabled = snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.metrics.is_some());
    match limits.validate_for_preflight(task_budget, listen_addresses.len(), metrics_enabled) {
        Ok(capacity) => {
            report.pass("capacity", capacity.summary());
        }
        Err(error) => {
            report.fail("capacity", error);
        }
    }

    match parsed_listeners {
        Ok(_) if ingress_configuration_valid => {
            match activated_listener::acquire(&listen_addresses) {
                Ok(listeners) => {
                    let acquired = listeners
                        .iter()
                        .map(|listener| {
                            let address = listener.listener.local_addr().map_or_else(
                                |_| "unknown".to_string(),
                                |address| address.to_string(),
                            );
                            format!("{:?}@{address}", listener.origin)
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    drop(listeners);
                    report.pass(
                        "listener acquisition",
                        format!("acquired and released {acquired} without calling accept"),
                    );
                }
                Err(error) => report.fail("listener acquisition", error),
            }
        }
        Ok(_) => report.fail(
            "listener acquisition",
            "not attempted because the public ingress configuration is invalid",
        ),
        Err(error) => report.fail("listener acquisition", error),
    }

    let connector = match TlsConnector::new() {
        Ok(connector) => {
            report.pass(
                "system trust roots",
                "initialized the platform TLS verifier with hostname verification enabled",
            );
            Some(connector)
        }
        Err(error) => {
            report.fail(
                "system trust roots",
                format!("cannot initialize the platform TLS verifier: {error}"),
            );
            None
        }
    };

    let assignments = match &paths {
        Some(paths) => match port_registry::read_logical_assignments(&paths.port_registry) {
            Ok(assignments) => Some(assignments),
            Err(error) => {
                report.fail("registrations", error);
                None
            }
        },
        None => None,
    };
    let route_targets = check_registrations(&mut report, snapshot.as_deref(), assignments.as_ref());
    check_route_certificates(
        &mut report,
        snapshot.as_deref(),
        assignments.as_ref(),
        route_targets,
        connector.as_ref(),
    );

    report.finish()
}

fn check_execution_identity(report: &mut Report) {
    #[cfg(unix)]
    {
        let uid = nix::unistd::geteuid();
        if uid.is_root() {
            report.fail(
                "execution identity",
                "preflight must run as the non-root production service identity",
            );
        } else {
            report.pass(
                "execution identity",
                format!("effective UID {} is non-root", uid.as_raw()),
            );
        }
    }
    #[cfg(not(unix))]
    report.fail(
        "execution identity",
        "the public Hosting Profile requires a Unix service identity",
    );
}

fn check_control_authorization(report: &mut Report, paths: &ProductionPaths, loopback_only: bool) {
    match paths.validate_preflight_control(!loopback_only) {
        Ok(gid) => report.pass(
            "control authorization",
            if loopback_only {
                format!(
                    "effective-user loopback control directory is ready with runtime GID {gid}"
                )
            } else {
                format!(
                    "control directory uses {} GID {gid}; read-only peers remain locally authenticated",
                    crate::production_paths::PUBLIC_CONTROL_GROUP
                )
            },
        ),
        Err(error) => report.fail("control authorization", error),
    }
}

fn check_registrations(
    report: &mut Report,
    snapshot: Option<&PublicIngressSnapshot>,
    assignments: Option<&port_registry::LogicalAssignments>,
) -> Vec<RouteTarget> {
    let (Some(snapshot), Some(assignments)) = (snapshot, assignments) else {
        if !report
            .checks
            .iter()
            .any(|check| check.name == "registrations")
        {
            report.fail(
                "registrations",
                "cannot resolve declared Workload/role assignments until config and registry checks pass",
            );
        }
        return Vec::new();
    };

    let mut targets = Vec::new();
    let mut required_missing = Vec::new();
    let mut optional_missing = Vec::new();
    for route in snapshot.routes.values() {
        let key = (route.workload.clone(), route.role.clone());
        match assignments.get(&key) {
            Some(port) => targets.push(RouteTarget {
                hostname: route.hostname.clone(),
                workload: route.workload.clone(),
                role: route.role.clone(),
                required: route.required,
                port: *port,
            }),
            None if route.required => required_missing.push(RouteIssue {
                hostname: route.hostname.clone(),
                workload: route.workload.clone(),
                role: route.role.clone(),
                detail: "registration is missing".to_string(),
            }),
            None => optional_missing.push(RouteIssue {
                hostname: route.hostname.clone(),
                workload: route.workload.clone(),
                role: route.role.clone(),
                detail: "optional registration is missing".to_string(),
            }),
        }
    }

    if !required_missing.is_empty() {
        report.fail(
            "registrations",
            format_route_issues(
                &format!(
                    "{} required declaration(s) lack a Port Registry assignment",
                    required_missing.len()
                ),
                &required_missing,
            ),
        );
    }
    if !optional_missing.is_empty() {
        report.warn(
            "registrations",
            format_route_issues(
                &format!(
                    "{} optional declaration(s) lack a Port Registry assignment",
                    optional_missing.len()
                ),
                &optional_missing,
            ),
        );
    }
    if required_missing.is_empty() && optional_missing.is_empty() {
        report.pass(
            "registrations",
            format!(
                "all {} declaration(s) resolve to unique loopback ports",
                snapshot.routes.len()
            ),
        );
    }
    targets
}

fn check_route_certificates(
    report: &mut Report,
    snapshot: Option<&PublicIngressSnapshot>,
    assignments: Option<&BTreeMap<(String, String), u16>>,
    targets: Vec<RouteTarget>,
    connector: Option<&TlsConnector>,
) {
    let (Some(snapshot), Some(assignments), Some(connector)) = (snapshot, assignments, connector)
    else {
        report.fail(
            "route certificates",
            "cannot verify exact-hostname certificates until config, registry, and trust-root checks pass",
        );
        return;
    };

    let mut required_failures = Vec::new();
    let mut optional_failures = Vec::new();
    for route in snapshot.routes.values() {
        if !assignments.contains_key(&(route.workload.clone(), route.role.clone())) {
            let issue = RouteIssue {
                hostname: route.hostname.clone(),
                workload: route.workload.clone(),
                role: route.role.clone(),
                detail: "registration is missing".to_string(),
            };
            if route.required {
                required_failures.push(issue);
            } else {
                optional_failures.push(issue);
            }
        }
    }
    for target in targets {
        if let Err(error) =
            proxy::verify_declared_route_certificate(&target.hostname, target.port, connector)
        {
            let issue = RouteIssue {
                hostname: target.hostname,
                workload: target.workload,
                role: target.role,
                detail: bounded_detail(&error),
            };
            if target.required {
                required_failures.push(issue);
            } else {
                optional_failures.push(issue);
            }
        }
    }

    if !required_failures.is_empty() {
        report.fail(
            "route certificates",
            format_route_issues(
                &format!(
                    "{} required route(s) failed loopback exact-hostname system-trust verification",
                    required_failures.len()
                ),
                &required_failures,
            ),
        );
    }
    if !optional_failures.is_empty() {
        report.warn(
            "route certificates",
            format_route_issues(
                &format!(
                    "{} optional route(s) failed loopback exact-hostname system-trust verification",
                    optional_failures.len()
                ),
                &optional_failures,
            ),
        );
    }
    if required_failures.is_empty() && optional_failures.is_empty() {
        report.pass(
            "route certificates",
            format!(
                "all {} declaration(s) passed loopback exact-hostname system-trust verification",
                snapshot.routes.len()
            ),
        );
    }
}

fn format_route_issues(summary: &str, issues: &[RouteIssue]) -> String {
    let mut detail = issues
        .iter()
        .take(MAX_REPORTED_ROUTE_FAILURES)
        .map(|issue| {
            format!(
                "{} -> {}/{} ({})",
                issue.hostname, issue.workload, issue.role, issue.detail
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if issues.len() > MAX_REPORTED_ROUTE_FAILURES {
        detail.push_str(&format!(
            "; {} additional failure(s) omitted",
            issues.len() - MAX_REPORTED_ROUTE_FAILURES
        ));
    }
    format!("{summary}: {detail}")
}

fn bounded_detail(detail: &str) -> String {
    let mut characters = detail.chars();
    let mut bounded = characters
        .by_ref()
        .take(MAX_FAILURE_DETAIL_LENGTH)
        .collect::<String>();
    if characters.next().is_some() {
        bounded.push_str("...");
    }
    bounded.replace(['\n', '\r'], " ")
}
