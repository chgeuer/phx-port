use crate::{port_registry, tls_client_hello};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use toml_edit::DocumentMut;

const INGRESS_CONFIG_ENV: &str = "PHX_PORT_INGRESS_CONFIG";
const MAX_ROLE_LENGTH: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDeclaration {
    pub hostname: String,
    pub workload: String,
    pub role: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostingProfile {
    Development,
    Public {
        ingress_config: PathBuf,
        route: RouteDeclaration,
    },
}

impl HostingProfile {
    pub fn load(explicit_path: Option<PathBuf>) -> Result<Self, String> {
        Self::load_with_env(explicit_path, std::env::var_os(INGRESS_CONFIG_ENV))
    }

    fn load_with_env(
        explicit_path: Option<PathBuf>,
        environment_path: Option<OsString>,
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

        let content = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read ingress config {}: {error}", path.display()))?;
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
                    "ingress config {} must contain exactly one [ingress.hosts] Route Declaration",
                    path.display()
                )
            })?;
        if hosts.len() != 1 {
            return Err(format!(
                "ingress config {} must contain exactly one Route Declaration, found {}",
                path.display(),
                hosts.len()
            ));
        }
        let (configured_hostname, declaration) = hosts
            .iter()
            .next()
            .expect("one Route Declaration was required");
        let hostname = tls_client_hello::normalize_hostname(configured_hostname).map_err(|_| {
            format!(
                "ingress config {} has invalid Route Declaration hostname {configured_hostname:?}",
                path.display()
            )
        })?;
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
        if role.is_empty()
            || role.len() > MAX_ROLE_LENGTH
            || !role.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err(format!(
                "ingress config {} Route Declaration {configured_hostname:?} role must contain 1 through {MAX_ROLE_LENGTH} lowercase ASCII letters, digits, '.', '_', or '-'",
                path.display()
            ));
        }
        if let Some(required) = declaration.get("required")
            && required.as_bool().is_none()
        {
            return Err(format!(
                "ingress config {} Route Declaration {configured_hostname:?} required must be a boolean",
                path.display()
            ));
        }

        Ok(Self::Public {
            ingress_config: path,
            route: RouteDeclaration {
                hostname,
                workload,
                role,
            },
        })
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public { .. })
    }

    pub fn route(&self, hostname: &str) -> Option<&RouteDeclaration> {
        match self {
            Self::Public { route, .. } if route.hostname == hostname => Some(route),
            Self::Development | Self::Public { .. } => None,
        }
    }

    pub fn declared_route(&self) -> Option<&RouteDeclaration> {
        match self {
            Self::Public { route, .. } => Some(route),
            Self::Development => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Public { .. } => "public",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HostingProfile, RouteDeclaration};
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

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

    #[test]
    fn development_is_the_default_without_an_explicit_ingress_config() {
        assert_eq!(
            HostingProfile::load_with_env(None, None).unwrap(),
            HostingProfile::Development
        );
    }

    #[test]
    fn cli_and_environment_paths_activate_only_explicit_public_mode() {
        let directory = tempdir().unwrap();
        let public = directory.path().join("public.toml");
        write_public_config(&public, "WWW.Example.COM.", "contoso-web");

        let from_cli = HostingProfile::load_with_env(Some(public.clone()), None).unwrap();
        assert_eq!(
            from_cli,
            HostingProfile::Public {
                ingress_config: public.clone(),
                route: RouteDeclaration {
                    hostname: "www.example.com".to_string(),
                    workload: "contoso-web".to_string(),
                    role: "https".to_string(),
                },
            }
        );
        assert_eq!(
            from_cli.route("www.example.com"),
            Some(&RouteDeclaration {
                hostname: "www.example.com".to_string(),
                workload: "contoso-web".to_string(),
                role: "https".to_string(),
            })
        );
        assert!(from_cli.route("undeclared.example.com").is_none());
        let from_environment =
            HostingProfile::load_with_env(None, Some(public.clone().into_os_string())).unwrap();
        assert_eq!(from_environment, from_cli);

        let development = directory.path().join("development.toml");
        fs::write(&development, "[ingress]\nmode = \"development\"\n").unwrap();
        let error = HostingProfile::load_with_env(Some(development), None).unwrap_err();
        assert!(error.contains("must declare [ingress] mode = \"public\""));
    }

    #[test]
    fn public_profile_requires_one_exact_rejecting_route() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");

        fs::write(&config, "[ingress]\nmode = \"public\"\n").unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config.clone()), None)
                .unwrap_err()
                .contains("exactly one [ingress.hosts] Route Declaration")
        );

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\nunknown_sni = \"discover\"\n\
             [ingress.hosts.\"www.example.com\"]\nworkload = \"contoso-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config.clone()), None)
                .unwrap_err()
                .contains("unknown_sni = \"reject\"")
        );

        fs::write(
            &config,
            "[ingress]\nmode = \"public\"\n\
             [ingress.hosts.\"www.example.com\"]\nworkload = \"contoso-web\"\nrole = \"https\"\n\
             [ingress.hosts.\"api.example.com\"]\nworkload = \"api-web\"\nrole = \"https\"\n",
        )
        .unwrap();
        assert!(
            HostingProfile::load_with_env(Some(config), None)
                .unwrap_err()
                .contains("exactly one Route Declaration, found 2")
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
            (
                "www.example.com",
                "contoso-web",
                "HTTPS",
                "role must contain",
            ),
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
            let error = HostingProfile::load_with_env(Some(config.clone()), None).unwrap_err();
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
            HostingProfile::load_with_env(Some(config), None)
                .unwrap_err()
                .contains("required must be a boolean")
        );
    }

    #[test]
    fn an_empty_environment_path_fails_instead_of_falling_back_to_development() {
        let error = HostingProfile::load_with_env(None, Some(OsString::new())).unwrap_err();
        assert_eq!(error, "PHX_PORT_INGRESS_CONFIG must not be empty");
    }
}
