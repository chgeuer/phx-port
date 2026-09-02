use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use toml_edit::DocumentMut;

const INGRESS_CONFIG_ENV: &str = "PHX_PORT_INGRESS_CONFIG";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostingProfile {
    Development,
    Public { ingress_config: PathBuf },
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

        Ok(Self::Public {
            ingress_config: path,
        })
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public { .. })
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
    use super::HostingProfile;
    use std::ffi::OsString;
    use std::fs;
    use tempfile::tempdir;

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
        fs::write(&public, "[ingress]\nmode = \"public\"\n").unwrap();

        let from_cli = HostingProfile::load_with_env(Some(public.clone()), None).unwrap();
        assert_eq!(
            from_cli,
            HostingProfile::Public {
                ingress_config: public.clone()
            }
        );
        let from_environment =
            HostingProfile::load_with_env(None, Some(public.clone().into_os_string())).unwrap();
        assert_eq!(from_environment, from_cli);

        let development = directory.path().join("development.toml");
        fs::write(&development, "[ingress]\nmode = \"development\"\n").unwrap();
        let error = HostingProfile::load_with_env(Some(development), None).unwrap_err();
        assert!(error.contains("must declare [ingress] mode = \"public\""));
    }

    #[test]
    fn an_empty_environment_path_fails_instead_of_falling_back_to_development() {
        let error = HostingProfile::load_with_env(None, Some(OsString::new())).unwrap_err();
        assert_eq!(error, "PHX_PORT_INGRESS_CONFIG must not be empty");
    }
}
