use crate::{
    port_registry,
    production_paths::{IntentOwner, read_ingress_intent},
    tls_client_hello,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use toml_edit::DocumentMut;

const INGRESS_CONFIG_ENV: &str = "PHX_PORT_INGRESS_CONFIG";
pub(crate) const MAX_ROUTE_DECLARATIONS: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDeclaration {
    pub hostname: String,
    pub workload: String,
    pub role: String,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIngressSnapshot {
    pub ingress_config: PathBuf,
    pub intent_owner: IntentOwner,
    pub generation: u64,
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
            if !matches!(key, "mode" | "unknown_sni" | "hosts") {
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
                if !matches!(key, "workload" | "role" | "required") {
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

            routes.insert(
                hostname.clone(),
                RouteDeclaration {
                    hostname,
                    workload,
                    role,
                    required,
                },
            );
        }

        Ok(Self::Public(Arc::new(PublicIngressSnapshot {
            ingress_config: path,
            intent_owner: owner,
            generation,
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
        if candidate_snapshot.routes == current.routes {
            return Ok(None);
        }
        Ok(Some(candidate))
    }

    #[cfg(test)]
    pub fn route(&self, hostname: &str) -> Option<&RouteDeclaration> {
        match self {
            Self::Public(snapshot) => snapshot.routes.get(hostname),
            Self::Development => None,
        }
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
    use super::{HostingProfile, MAX_ROUTE_DECLARATIONS, PublicIngressSnapshot, RouteDeclaration};
    use crate::production_paths::IntentOwner;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
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
            HostingProfile::load_with_env(Some(config), None, IntentOwner::EffectiveUser)
                .unwrap_err()
                .contains("required must be a boolean")
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
    fn an_empty_environment_path_fails_instead_of_falling_back_to_development() {
        let error =
            HostingProfile::load_with_env(None, Some(OsString::new()), IntentOwner::EffectiveUser)
                .unwrap_err();
        assert_eq!(error, "PHX_PORT_INGRESS_CONFIG must not be empty");
    }
}
