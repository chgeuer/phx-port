use crate::{
    port_registry,
    production_paths::{IntentOwner, read_ingress_intent},
    tls_client_hello,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use toml_edit::{DocumentMut, Table};

const INGRESS_CONFIG_ENV: &str = "PHX_PORT_INGRESS_CONFIG";
pub(crate) const MAX_ROUTE_DECLARATIONS: usize = 1_000;
pub(crate) const DEFAULT_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_INGRESS_LISTENERS: usize = 2;
const MAX_SOURCE_DIAGNOSTIC_DURATION_SECONDS: u64 = 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsConfig {
    pub listen: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDiagnosticsConfig {
    pub sample_every: u64,
    pub expires_at_unix_seconds: u64,
}

impl SourceDiagnosticsConfig {
    pub fn active_at(self, unix_seconds: u64) -> bool {
        unix_seconds < self.expires_at_unix_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDeclaration {
    pub hostname: String,
    pub workload: String,
    pub role: String,
    pub required: bool,
    pub relay_idle_timeout: Option<Duration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIngressSnapshot {
    pub ingress_config: PathBuf,
    pub intent_owner: IntentOwner,
    pub generation: u64,
    pub listeners: Option<Vec<SocketAddr>>,
    pub metrics: Option<MetricsConfig>,
    pub source_diagnostics: Option<SourceDiagnosticsConfig>,
    pub routes: BTreeMap<String, RouteDeclaration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostingProfile {
    Development,
    Public(Arc<PublicIngressSnapshot>),
}

impl HostingProfile {
    #[cfg(test)]
    pub fn load(explicit_path: Option<PathBuf>) -> Result<Self, String> {
        Self::load_with_owner(explicit_path, IntentOwner::EffectiveUser)
    }

    pub fn load_for_daemon(
        explicit_path: Option<PathBuf>,
        loopback_only: bool,
    ) -> Result<Self, String> {
        let owner = if loopback_only {
            IntentOwner::EffectiveUser
        } else {
            IntentOwner::Root
        };
        Self::load_with_owner(explicit_path, owner)
    }

    pub fn load_for_check(path: PathBuf) -> Result<Self, String> {
        Self::load_with_env(Some(path), None, IntentOwner::Root)
    }

    fn load_with_owner(explicit_path: Option<PathBuf>, owner: IntentOwner) -> Result<Self, String> {
        Self::load_with_env(explicit_path, std::env::var_os(INGRESS_CONFIG_ENV), owner)
    }

    fn load_with_env(
        explicit_path: Option<PathBuf>,
        environment_path: Option<OsString>,
        owner: IntentOwner,
    ) -> Result<Self, String> {
        let path = match explicit_path {
            Some(path) => path,
            None => match environment_path {
                Some(path) if path.is_empty() => {
                    return Err(format!("{INGRESS_CONFIG_ENV} must not be empty"));
                }
                Some(path) => PathBuf::from(path),
                None => return Ok(Self::Development),
            },
        };
        if path.as_os_str().is_empty() {
            return Err("ingress config path must not be empty".to_string());
        }

        Self::load_public(path, 1, owner)
    }

    fn load_public(path: PathBuf, generation: u64, owner: IntentOwner) -> Result<Self, String> {
        let content = read_ingress_intent(&path, owner)?;
        let document = content
            .parse::<DocumentMut>()
            .map_err(|error| format!("cannot parse ingress config {}: {error}", path.display()))?;
        let mode = document
            .get("ingress")
            .and_then(|item| item.as_table())
            .and_then(|ingress| ingress.get("mode"))
            .and_then(|item| item.as_str());
        if mode != Some("public") {
            return Err(format!(
                "ingress config {} must declare [ingress] mode = \"public\"",
                path.display()
            ));
        }
        let ingress = document
            .get("ingress")
            .and_then(|item| item.as_table())
            .expect("the public mode was read from an ingress table");
        for (key, _) in ingress {
            if !matches!(
                key,
                "mode" | "unknown_sni" | "listen" | "metrics" | "source_diagnostics" | "hosts"
            ) {
                return Err(format!(
                    "ingress config {} contains unknown [ingress] key {key:?}",
                    path.display()
                ));
            }
        }
        if let Some(unknown_sni) = ingress.get("unknown_sni")
            && unknown_sni.as_str() != Some("reject")
        {
            return Err(format!(
                "ingress config {} must set unknown_sni = \"reject\" when present",
                path.display()
            ));
        }
        let listeners = match ingress.get("listen") {
            None => None,
            Some(item) => {
                let configured = item.as_array().ok_or_else(|| {
                    format!(
                        "ingress config {} [ingress] listen must be an array of socket addresses",
                        path.display()
                    )
                })?;
                if configured.is_empty() {
                    return Err(format!(
                        "ingress config {} [ingress] listen must contain at least one socket address",
                        path.display()
                    ));
                }
                if configured.len() > MAX_INGRESS_LISTENERS {
                    return Err(format!(
                        "ingress config {} [ingress] listen contains {} addresses, exceeding the limit of {MAX_INGRESS_LISTENERS}",
                        path.display(),
                        configured.len()
                    ));
                }
                let mut parsed = Vec::with_capacity(configured.len());
                for value in configured {
                    let value = value.as_str().ok_or_else(|| {
                        format!(
                            "ingress config {} [ingress] listen entries must be strings",
                            path.display()
                        )
                    })?;
                    let address = value.parse::<SocketAddr>().map_err(|error| {
                        format!(
                            "ingress config {} has invalid listener address {value:?}: {error}",
                            path.display()
                        )
                    })?;
                    if address.port() == 0 {
                        return Err(format!(
                            "ingress config {} listener address {value:?} must use a nonzero port",
                            path.display()
                        ));
                    }
                    if parsed.iter().any(|existing: &SocketAddr| {
                        existing == &address || existing.is_ipv4() == address.is_ipv4()
                    }) {
                        return Err(format!(
                            "ingress config {} [ingress] listen may declare at most one unique IPv4 and one unique IPv6 address",
                            path.display()
                        ));
                    }
                    parsed.push(address);
                }
                parsed.sort_unstable();
                Some(parsed)
            }
        };
        let metrics = Self::parse_metrics_config(ingress, &path)?;
        let source_diagnostics_reference_time = SystemTime::now();
        let source_diagnostics = Self::parse_source_diagnostics_config(
            ingress,
            &path,
            source_diagnostics_reference_time,
        )?;

        let hosts = ingress
            .get("hosts")
            .and_then(|item| item.as_table())
            .ok_or_else(|| {
                format!(
                    "ingress config {} must contain [ingress.hosts] Route Declarations",
                    path.display()
                )
            })?;
        if hosts.is_empty() {
            return Err(format!(
                "ingress config {} must contain at least one Route Declaration",
                path.display()
            ));
        }
        if hosts.len() > MAX_ROUTE_DECLARATIONS {
            return Err(format!(
                "ingress config {} contains {} Route Declarations, exceeding the limit of {MAX_ROUTE_DECLARATIONS}",
                path.display(),
                hosts.len()
            ));
        }

        let mut routes = BTreeMap::new();
        let mut configured_names = BTreeMap::<String, String>::new();
        for (configured_hostname, declaration) in hosts {
            let hostname =
                tls_client_hello::normalize_hostname(configured_hostname).map_err(|_| {
                    format!(
                        "ingress config {} has invalid Route Declaration hostname {configured_hostname:?}",
                        path.display()
                    )
                })?;
            if let Some(previous) =
                configured_names.insert(hostname.clone(), configured_hostname.to_string())
            {
                return Err(format!(
                    "ingress config {} Route Declaration hostnames {previous:?} and {configured_hostname:?} both normalize to {hostname:?}",
                    path.display()
                ));
            }

            let declaration = declaration.as_table().ok_or_else(|| {
                format!(
                    "ingress config {} Route Declaration {configured_hostname:?} must be a table",
                    path.display()
                )
            })?;
            for (key, _) in declaration {
                if !matches!(
                    key,
                    "workload" | "role" | "required" | "relay_idle_timeout_seconds"
                ) {
                    return Err(format!(
                        "ingress config {} Route Declaration {configured_hostname:?} contains unknown key {key:?}",
                        path.display()
                    ));
                }
            }
            let workload = declaration
                .get("workload")
                .and_then(|item| item.as_str())
                .ok_or_else(|| {
                    format!(
                        "ingress config {} Route Declaration {configured_hostname:?} requires a string workload",
                        path.display()
                    )
                })?
                .to_string();
            port_registry::validate_workload_id(&workload).map_err(|error| {
                format!(
                    "ingress config {} Route Declaration {configured_hostname:?} has invalid Workload ID {workload:?}: {error}",
                    path.display()
                )
            })?;
            let role = declaration
                .get("role")
                .and_then(|item| item.as_str())
                .ok_or_else(|| {
                    format!(
                        "ingress config {} Route Declaration {configured_hostname:?} requires a string role",
                        path.display()
                    )
                })?
                .to_string();
            port_registry::validate_role(&role).map_err(|error| {
                format!(
                    "ingress config {} Route Declaration {configured_hostname:?} has invalid role {role:?}: {error}",
                    path.display()
                )
            })?;
            let required = match declaration.get("required") {
                Some(required) => required.as_bool().ok_or_else(|| {
                    format!(
                        "ingress config {} Route Declaration {configured_hostname:?} required must be a boolean",
                        path.display()
                    )
                })?,
                None => false,
            };
            let relay_idle_timeout = match declaration.get("relay_idle_timeout_seconds") {
                None => Some(DEFAULT_RELAY_IDLE_TIMEOUT),
                configured => {
                    let seconds = Self::parse_nonnegative_u64(
                        configured,
                        &path,
                        &format!(
                            "Route Declaration {configured_hostname:?} relay_idle_timeout_seconds"
                        ),
                    )?;
                    if seconds == 0 {
                        None
                    } else if seconds < DEFAULT_RELAY_IDLE_TIMEOUT.as_secs() {
                        return Err(format!(
                            "ingress config {} Route Declaration {configured_hostname:?} \
                             relay_idle_timeout_seconds must be 0 to disable or at least {}",
                            path.display(),
                            DEFAULT_RELAY_IDLE_TIMEOUT.as_secs()
                        ));
                    } else {
                        let timeout = Duration::from_secs(seconds);
                        if Instant::now().checked_add(timeout).is_none() {
                            return Err(format!(
                                "ingress config {} Route Declaration {configured_hostname:?} \
                                 relay_idle_timeout_seconds is too large for the monotonic timer",
                                path.display()
                            ));
                        }
                        Some(timeout)
                    }
                }
            };

            routes.insert(
                hostname.clone(),
                RouteDeclaration {
                    hostname,
                    workload,
                    role,
                    required,
                    relay_idle_timeout,
                },
            );
        }

        Ok(Self::Public(Arc::new(PublicIngressSnapshot {
            ingress_config: path,
            intent_owner: owner,
            generation,
            listeners,
            metrics,
            source_diagnostics,
            routes,
        })))
    }

    pub fn reload(&self) -> Result<Option<Self>, String> {
        let Self::Public(current) = self else {
            return Ok(None);
        };
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| "ingress config generation overflowed".to_string())?;
        let candidate = Self::load_public(
            current.ingress_config.clone(),
            generation,
            current.intent_owner,
        )?;
        let Self::Public(candidate_snapshot) = &candidate else {
            unreachable!("loading an explicit public config returns a public snapshot");
        };
        if candidate_snapshot.listeners != current.listeners {
            return Err(
                "public ingress listener declarations cannot change during reload".to_string(),
            );
        }
        if candidate_snapshot.metrics != current.metrics {
            return Err(
                "public metrics listener declaration cannot change during reload".to_string(),
            );
        }
        if candidate_snapshot.routes == current.routes
            && candidate_snapshot.source_diagnostics == current.source_diagnostics
        {
            return Ok(None);
        }
        Ok(Some(candidate))
    }

    pub fn validate_daemon_listeners(
        &self,
        configured_addresses: &[String],
        require_declarations: bool,
    ) -> Result<(), String> {
        if matches!(self, Self::Development) {
            return Ok(());
        }
        let configured = configured_addresses
            .iter()
            .map(|configured| {
                configured.parse::<SocketAddr>().map_err(|error| {
                    format!("invalid ingress listener address {configured:?}: {error}")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.validate_bound_listeners(&configured, require_declarations)
    }

    pub fn validate_bound_listeners(
        &self,
        bound_addresses: &[SocketAddr],
        require_declarations: bool,
    ) -> Result<(), String> {
        let Self::Public(snapshot) = self else {
            return Ok(());
        };
        let Some(expected) = snapshot.listeners.as_ref() else {
            if require_declarations {
                return Err(
                    "manual --run-as public startup requires [ingress] listen declarations"
                        .to_string(),
                );
            }
            return Ok(());
        };

        let mut actual = bound_addresses.to_vec();
        actual.sort_unstable();
        if actual != *expected {
            return Err(format!(
                "bound daemon listeners {actual:?} do not match public [ingress] listen declarations {expected:?}"
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn route(&self, hostname: &str) -> Option<&RouteDeclaration> {
        match self {
            Self::Public(snapshot) => snapshot.routes.get(hostname),
            Self::Development => None,
        }
    }

    fn parse_metrics_config(
        ingress: &Table,
        path: &std::path::Path,
    ) -> Result<Option<MetricsConfig>, String> {
        let Some(metrics) = ingress.get("metrics") else {
            return Ok(None);
        };
        let metrics = metrics.as_table().ok_or_else(|| {
            format!(
                "ingress config {} [ingress.metrics] must be a table",
                path.display()
            )
        })?;
        for (key, _) in metrics {
            if key != "listen" {
                return Err(format!(
                    "ingress config {} contains unknown [ingress.metrics] key {key:?}",
                    path.display()
                ));
            }
        }
        let configured = metrics
            .get("listen")
            .and_then(|item| item.as_str())
            .ok_or_else(|| {
                format!(
                    "ingress config {} [ingress.metrics] requires a string listen address",
                    path.display()
                )
            })?;
        let listen = configured.parse::<SocketAddr>().map_err(|error| {
            format!(
                "ingress config {} has invalid metrics listen address {configured:?}: {error}",
                path.display()
            )
        })?;
        if listen.port() == 0 {
            return Err(format!(
                "ingress config {} metrics listen address {configured:?} must use a nonzero port",
                path.display()
            ));
        }
        if !listen.ip().is_loopback() {
            return Err(format!(
                "ingress config {} metrics listen address {configured:?} must be loopback-only",
                path.display()
            ));
        }
        Ok(Some(MetricsConfig { listen }))
    }

    fn parse_source_diagnostics_config(
        ingress: &Table,
        path: &std::path::Path,
        reference_time: SystemTime,
    ) -> Result<Option<SourceDiagnosticsConfig>, String> {
        let Some(diagnostics) = ingress.get("source_diagnostics") else {
            return Ok(None);
        };
        let diagnostics = diagnostics.as_table().ok_or_else(|| {
            format!(
                "ingress config {} [ingress.source_diagnostics] must be a table",
                path.display()
            )
        })?;
        for (key, _) in diagnostics {
            if !matches!(key, "sample_every" | "expires_at_unix_seconds") {
                return Err(format!(
                    "ingress config {} contains unknown [ingress.source_diagnostics] key {key:?}",
                    path.display()
                ));
            }
        }
        let sample_every = Self::parse_positive_u64(
            diagnostics.get("sample_every"),
            path,
            "[ingress.source_diagnostics] sample_every",
        )?;
        let expires_at_unix_seconds = Self::parse_nonnegative_u64(
            diagnostics.get("expires_at_unix_seconds"),
            path,
            "[ingress.source_diagnostics] expires_at_unix_seconds",
        )?;
        let now = reference_time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_string())?
            .as_secs();
        let latest = now.saturating_add(MAX_SOURCE_DIAGNOSTIC_DURATION_SECONDS);
        if expires_at_unix_seconds > latest {
            return Err(format!(
                "ingress config {} source diagnostics expiry must be no more than {MAX_SOURCE_DIAGNOSTIC_DURATION_SECONDS} seconds in the future",
                path.display()
            ));
        }
        Ok(Some(SourceDiagnosticsConfig {
            sample_every,
            expires_at_unix_seconds,
        }))
    }

    fn parse_positive_u64(
        item: Option<&toml_edit::Item>,
        path: &std::path::Path,
        field: &str,
    ) -> Result<u64, String> {
        let value = Self::parse_nonnegative_u64(item, path, field)?;
        if value == 0 {
            return Err(format!(
                "ingress config {} {field} must be greater than zero",
                path.display()
            ));
        }
        Ok(value)
    }

    fn parse_nonnegative_u64(
        item: Option<&toml_edit::Item>,
        path: &std::path::Path,
        field: &str,
    ) -> Result<u64, String> {
        let value = item
            .and_then(|item| item.as_integer())
            .ok_or_else(|| format!("ingress config {} requires integer {field}", path.display()))?;
        u64::try_from(value).map_err(|_| {
            format!(
                "ingress config {} {field} must be nonnegative",
                path.display()
            )
        })
    }

    pub fn public_snapshot(&self) -> Option<Arc<PublicIngressSnapshot>> {
        match self {
            Self::Public(snapshot) => Some(Arc::clone(snapshot)),
            Self::Development => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Public(_) => "public",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RELAY_IDLE_TIMEOUT, HostingProfile, MAX_ROUTE_DECLARATIONS,
        MAX_SOURCE_DIAGNOSTIC_DURATION_SECONDS, PublicIngressSnapshot, RouteDeclaration,
    };
    use crate::production_paths::IntentOwner;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempfile::{TempDir, tempdir_in};

    fn tempdir() -> std::io::Result<TempDir> {
        #[cfg(unix)]
        let root = Path::new("/tmp").canonicalize()?;
        #[cfg(not(unix))]
        let root = std::env::temp_dir().canonicalize()?;
        tempdir_in(root)
    }

    fn write_public_config(path: &Path, hostname: &str, workload: &str) {
        fs::write(
            path,
            format!(
                "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n\n\
                 [ingress.hosts.\"{hostname}\"]\n\
                 workload = \"{workload}\"\nrole = \"https\"\nrequired = true\n"
            ),
        )
        .unwrap();
    }

    fn route(hostname: &str, workload: &str, required: bool) -> RouteDeclaration {
        RouteDeclaration {
            hostname: hostname.to_string(),
            workload: workload.to_string(),
            role: "https".to_string(),
            required,
            relay_idle_timeout: Some(DEFAULT_RELAY_IDLE_TIMEOUT),
        }
    }

    #[test]
    fn development_is_the_default_without_an_explicit_ingress_config() {
        assert_eq!(
            HostingProfile::load_with_env(None, None, IntentOwner::EffectiveUser).unwrap(),
            HostingProfile::Development
        );
    }

    #[test]
    fn cli_and_environment_paths_activate_only_explicit_public_mode() {
        let directory = tempdir().unwrap();
        let public = directory.path().join("public.toml");
        write_public_config(&public, "WWW.Example.COM.", "contoso-web");

        let from_cli =
            HostingProfile::load_with_env(Some(public.clone()), None, IntentOwner::EffectiveUser)
                .unwrap();
        let mut routes = BTreeMap::new();
        routes.insert(
            "www.example.com".to_string(),
            route("www.example.com", "contoso-web", true),
        );
        assert_eq!(
            from_cli,
            HostingProfile::Public(Arc::new(PublicIngressSnapshot {
                ingress_config: public.clone(),
                intent_owner: IntentOwner::EffectiveUser,
                generation: 1,
                listeners: None,
                metrics: None,
                source_diagnostics: None,
                routes,
            }))
        );
        assert_eq!(
            from_cli.route("www.example.com"),
            Some(&route("www.example.com", "contoso-web", true))
        );
        assert!(from_cli.route("undeclared.example.com").is_none());
        let from_environment = HostingProfile::load_with_env(
            None,
            Some(public.clone().into_os_string()),
            IntentOwner::EffectiveUser,
        )
        .unwrap();
        assert_eq!(from_environment, from_cli);

        let development = directory.path().join("development.toml");
        fs::write(&development, "[ingress]\nmode = \"development\"\n").unwrap();
        let error =
            HostingProfile::load_with_env(Some(development), None, IntentOwner::EffectiveUser)
                .unwrap_err();
        assert!(error.contains("must declare [ingress] mode = \"public\""));
    }

    #[test]
    fn public_profile_accepts_multiple_bounded_exact_routes() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");

        fs::write(&config, "[ingress]\nmode = \"public\"\n").unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser,)
                .unwrap_err()
                .contains("[ingress.hosts] Route Declarations")
        );

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\nunknown_sni = \"discover\"\n\
             [ingress.hosts.\"www.example.com\"]\nworkload = \"contoso-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser,)
                .unwrap_err()
                .contains("unknown_sni = \"reject\"")
        );

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\nworkload = \"contoso-web\"\nrole = \"https\"\nrequired = true\n\
             [ingress.hosts.\"api.example.com\"]\nworkload = \"api-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        let profile =
            HostingProfile::load_with_env(Some(config), None, IntentOwner::EffectiveUser).unwrap();
        let snapshot = profile.public_snapshot().unwrap();
        assert_eq!(snapshot.routes.len(), 2);
        assert!(snapshot.routes["www.example.com"].required);
        assert!(!snapshot.routes["api.example.com"].required);
    }

    #[test]
    fn public_routes_support_default_override_and_disabled_relay_idle_policy() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"default.example.com\"]\n\
             workload = \"default-web\"\nrole = \"https\"\n\
             [ingress.hosts.\"extended.example.com\"]\n\
             workload = \"extended-web\"\nrole = \"https\"\n\
             relay_idle_timeout_seconds = 3600\n\
             [ingress.hosts.\"disabled.example.com\"]\n\
             workload = \"disabled-web\"\nrole = \"https\"\n\
             relay_idle_timeout_seconds = 0\n",
        )
        .unwrap();

        let profile =
            HostingProfile::load_with_env(Some(config), None, IntentOwner::EffectiveUser).unwrap();
        let routes = profile.public_snapshot().unwrap();
        assert_eq!(
            routes.routes["default.example.com"].relay_idle_timeout,
            Some(DEFAULT_RELAY_IDLE_TIMEOUT)
        );
        assert_eq!(
            routes.routes["extended.example.com"].relay_idle_timeout,
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            routes.routes["disabled.example.com"].relay_idle_timeout,
            None
        );
    }

    #[test]
    fn public_listener_declarations_are_bounded_and_match_daemon_addresses_exactly() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             listen = [\"[::]:443\", \"0.0.0.0:443\"]\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        let profile =
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser)
                .unwrap();
        profile
            .validate_daemon_listeners(&["0.0.0.0:443".to_string(), "[::]:443".to_string()], true)
            .unwrap();
        let error = profile
            .validate_daemon_listeners(&["127.0.0.1:443".to_string()], true)
            .unwrap_err();
        assert!(error.contains("do not match"), "{error}");

        for listeners in [
            "[]",
            "[\"127.0.0.1:0\"]",
            "[\"127.0.0.1:443\", \"0.0.0.0:443\"]",
            "[\"127.0.0.1:443\", \"[::1]:443\", \"[::]:443\"]",
        ] {
            fs::write(
                &config,
                format!(
                    "[ingress]\nmode = \"public\"\nlisten = {listeners}\n\
                     [ingress.hosts.\"www.example.com\"]\n\
                     workload = \"contoso-web\"\nrole = \"https\"\n"
                ),
            )
            .unwrap();
            assert!(
                HostingProfile::load_with_env(
                    Some(config.clone()),
                    None,
                    IntentOwner::EffectiveUser,
                )
                .is_err(),
                "unsafe listener declarations were accepted: {listeners}"
            );
        }
    }

    #[test]
    fn public_observability_is_loopback_only_bounded_and_explicitly_expiring() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let write_config = |metrics: &str, diagnostics: &str| {
            fs::write(
                &config,
                format!(
                    "[ingress]\nmode = \"public\"\n\
                     {metrics}\n\
                     {diagnostics}\n\
                     [ingress.hosts.\"www.example.com\"]\n\
                     workload = \"contoso-web\"\nrole = \"https\"\n"
                ),
            )
            .unwrap();
        };

        write_config(
            "[ingress.metrics]\nlisten = \"127.0.0.1:9464\"",
            &format!(
                "[ingress.source_diagnostics]\n\
                 sample_every = 100\n\
                 expires_at_unix_seconds = {}",
                now + 60
            ),
        );
        let profile =
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser)
                .unwrap();
        let snapshot = profile.public_snapshot().unwrap();
        assert_eq!(
            snapshot.metrics.unwrap().listen,
            "127.0.0.1:9464".parse().unwrap()
        );
        assert_eq!(snapshot.source_diagnostics.unwrap().sample_every, 100);
        assert!(snapshot.source_diagnostics.unwrap().active_at(now));

        for (metrics, expected) in [
            (
                "[ingress.metrics]\nlisten = \"0.0.0.0:9464\"",
                "loopback-only",
            ),
            (
                "[ingress.metrics]\nlisten = \"127.0.0.1:0\"",
                "nonzero port",
            ),
            (
                "[ingress.metrics]\nlisten = \"127.0.0.1:9464\"\nmutation = true",
                "unknown [ingress.metrics] key",
            ),
        ] {
            write_config(metrics, "");
            let error = HostingProfile::load_with_env(
                Some(config.clone()),
                None,
                IntentOwner::EffectiveUser,
            )
            .unwrap_err();
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        for (diagnostics, expected) in [
            (
                format!(
                    "[ingress.source_diagnostics]\n\
                     sample_every = 0\n\
                     expires_at_unix_seconds = {}",
                    now + 60
                ),
                "sample_every must be greater than zero",
            ),
            (
                "[ingress.source_diagnostics]\nsample_every = 1".to_string(),
                "requires integer [ingress.source_diagnostics] expires_at_unix_seconds",
            ),
        ] {
            write_config("", &diagnostics);
            let error = HostingProfile::load_with_env(
                Some(config.clone()),
                None,
                IntentOwner::EffectiveUser,
            )
            .unwrap_err();
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        write_config(
            "",
            &format!(
                "[ingress.source_diagnostics]\n\
                 sample_every = 1\n\
                 expires_at_unix_seconds = {}",
                now.saturating_sub(1)
            ),
        );
        let expired =
            HostingProfile::load_with_env(Some(config), None, IntentOwner::EffectiveUser).unwrap();
        assert!(
            !expired
                .public_snapshot()
                .unwrap()
                .source_diagnostics
                .unwrap()
                .active_at(now)
        );
    }

    #[test]
    fn source_diagnostic_expiry_uses_explicit_reference_instant() {
        const REFERENCE_UNIX_SECONDS: u64 = 1_000_000;
        let reference_time = UNIX_EPOCH + Duration::from_secs(REFERENCE_UNIX_SECONDS);
        let parse_at_offset = |offset| {
            let document = format!(
                "[ingress.source_diagnostics]\n\
                 sample_every = 1\n\
                 expires_at_unix_seconds = {}",
                REFERENCE_UNIX_SECONDS + offset
            )
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
            let ingress = document
                .get("ingress")
                .and_then(|item| item.as_table())
                .unwrap();
            HostingProfile::parse_source_diagnostics_config(
                ingress,
                Path::new("ingress.toml"),
                reference_time,
            )
        };

        let at_limit = parse_at_offset(MAX_SOURCE_DIAGNOSTIC_DURATION_SECONDS)
            .unwrap()
            .unwrap();
        assert_eq!(
            at_limit.expires_at_unix_seconds,
            REFERENCE_UNIX_SECONDS + MAX_SOURCE_DIAGNOSTIC_DURATION_SECONDS
        );

        let error = parse_at_offset(MAX_SOURCE_DIAGNOSTIC_DURATION_SECONDS + 1).unwrap_err();
        assert!(
            error.contains("no more than 3600 seconds in the future"),
            "{error}"
        );
    }

    #[test]
    fn metrics_listener_is_reload_immutable_but_diagnostics_can_change() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let write_config = |metrics_port: u16, expiry: u64| {
            fs::write(
                &config,
                format!(
                    "[ingress]\nmode = \"public\"\n\
                     [ingress.metrics]\nlisten = \"127.0.0.1:{metrics_port}\"\n\
                     [ingress.source_diagnostics]\n\
                     sample_every = 10\nexpires_at_unix_seconds = {expiry}\n\
                     [ingress.hosts.\"www.example.com\"]\n\
                     workload = \"contoso-web\"\nrole = \"https\"\n"
                ),
            )
            .unwrap();
        };

        write_config(9464, now + 60);
        let profile =
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser)
                .unwrap();
        write_config(9464, now + 120);
        let replacement = profile.reload().unwrap().unwrap();
        assert_eq!(replacement.public_snapshot().unwrap().generation, 2);
        assert_eq!(
            replacement
                .public_snapshot()
                .unwrap()
                .source_diagnostics
                .unwrap()
                .expires_at_unix_seconds,
            now + 120
        );

        write_config(9465, now + 120);
        let error = replacement.reload().unwrap_err();
        assert!(
            error.contains("metrics listener declaration cannot change during reload"),
            "{error}"
        );
        assert_eq!(replacement.public_snapshot().unwrap().generation, 2);
    }

    #[test]
    fn manual_public_startup_requires_listener_declarations() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        write_public_config(&config, "www.example.com", "contoso-web");
        let profile =
            HostingProfile::load_with_env(Some(config), None, IntentOwner::EffectiveUser).unwrap();
        let error = profile
            .validate_daemon_listeners(&["127.0.0.1:443".to_string()], true)
            .unwrap_err();
        assert!(error.contains("requires [ingress] listen"), "{error}");
    }

    #[test]
    fn public_profile_rejects_normalized_duplicates_and_excess_declarations() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"WWW.Example.COM.\"]\nworkload = \"first-web\"\nrole = \"https\"\n\
             [ingress.hosts.\"www.example.com\"]\nworkload = \"second-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        let error =
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser)
                .unwrap_err();
        assert!(
            error.contains("both normalize to \"www.example.com\""),
            "{error}"
        );

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\nworkload = \"first-web\"\nrole = \"https\"\n\
             [ingress.hosts.\"www.example.com\"]\nworkload = \"second-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        let error =
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser)
                .unwrap_err();
        assert!(error.contains("cannot parse ingress config"), "{error}");

        let mut content = String::from("[ingress]\nmode = \"public\"\n");
        for index in 0..=MAX_ROUTE_DECLARATIONS {
            content.push_str(&format!(
                "[ingress.hosts.\"host-{index}.example.test\"]\n\
                 workload = \"workload-{index}\"\nrole = \"https\"\n"
            ));
        }
        fs::write(&config, content).unwrap();
        let error = HostingProfile::load_with_env(Some(config), None, IntentOwner::EffectiveUser)
            .unwrap_err();
        assert!(
            error.contains("exceeding the limit of 1000"),
            "unexpected declaration bound error: {error}"
        );
    }

    #[test]
    fn public_route_identity_and_fields_fail_closed() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");

        for (hostname, workload, role, expected) in [
            (
                "*.example.com",
                "contoso-web",
                "https",
                "invalid Route Declaration hostname",
            ),
            (
                "www.example.com",
                "../contoso",
                "https",
                "invalid Workload ID",
            ),
            ("www.example.com", "contoso-web", "HTTPS", "invalid role"),
        ] {
            fs::write(
                &config,
                format!(
                    "[ingress]\nmode = \"public\"\n\
                     [ingress.hosts.\"{hostname}\"]\n\
                     workload = \"{workload}\"\nrole = \"{role}\"\n"
                ),
            )
            .unwrap();
            let error = HostingProfile::load_with_env(
                Some(config.clone()),
                None,
                IntentOwner::EffectiveUser,
            )
            .unwrap_err();
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\nrequired = \"yes\"\n",
        )
        .unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser,)
                .unwrap_err()
                .contains("required must be a boolean")
        );

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\n\
             relay_idle_timeout_seconds = -1\n",
        )
        .unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser,)
                .unwrap_err()
                .contains("relay_idle_timeout_seconds must be nonnegative")
        );

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\n\
             relay_idle_timeout_seconds = 1799\n",
        )
        .unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config), None, IntentOwner::EffectiveUser)
                .unwrap_err()
                .contains("must be 0 to disable or at least 1800")
        );
    }

    #[test]
    fn reload_rejects_invalid_content_and_advances_only_changed_valid_generations() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        write_public_config(&config, "www.example.com", "contoso-web");
        let profile =
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser)
                .unwrap();

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"DUPLICATE.example.com.\"]\nworkload = \"first-web\"\nrole = \"https\"\n\
             [ingress.hosts.\"duplicate.example.com\"]\nworkload = \"second-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        assert!(profile.reload().is_err());
        assert_eq!(profile.public_snapshot().unwrap().generation, 1);

        write_public_config(&config, "www.example.com", "contoso-web");
        assert_eq!(profile.reload().unwrap(), None);

        write_public_config(&config, "api.example.com", "api-web");
        let replacement = profile.reload().unwrap().unwrap();
        let snapshot = replacement.public_snapshot().unwrap();
        assert_eq!(snapshot.generation, 2);
        assert!(snapshot.routes.contains_key("api.example.com"));
        assert!(!snapshot.routes.contains_key("www.example.com"));
    }

    #[test]
    fn reload_rejects_listener_changes() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\nlisten = [\"127.0.0.1:443\"]\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        let profile =
            HostingProfile::load_with_env(Some(config.clone()), None, IntentOwner::EffectiveUser)
                .unwrap();
        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\nlisten = [\"127.0.0.1:8443\"]\n\
             [ingress.hosts.\"www.example.com\"]\n\
             workload = \"contoso-web\"\nrole = \"https\"\n",
        )
        .unwrap();

        let error = profile.reload().unwrap_err();
        assert!(error.contains("cannot change during reload"), "{error}");
        assert_eq!(profile.public_snapshot().unwrap().generation, 1);
    }

    #[test]
    fn an_empty_environment_path_fails_instead_of_falling_back_to_development() {
        let error =
            HostingProfile::load_with_env(None, Some(OsString::new()), IntentOwner::EffectiveUser)
                .unwrap_err();
        assert_eq!(error, "PHX_PORT_INGRESS_CONFIG must not be empty");
    }
}
