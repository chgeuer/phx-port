use crate::{port_registry, tls_client_hello};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use toml_edit::{DocumentMut, value};

const TABLE: &str = "discovered_routes";
const MAX_CACHED_ROUTES: usize = 1024;
const MAX_FINGERPRINT_LENGTH: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Storage {
    CombinedRegistry,
    SeparateState,
}

impl Storage {
    fn security(self) -> port_registry::RegistrySecurity {
        match self {
            Self::CombinedRegistry => port_registry::RegistrySecurity::Development,
            Self::SeparateState => port_registry::RegistrySecurity::DerivedState,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedRoute {
    pub project: String,
    pub role: String,
    pub certificate_fingerprint: String,
}

pub fn validate(path: &Path, storage: Storage) -> Result<(), String> {
    let document = port_registry::read(path, storage.security())?;
    validate_document(&document, storage)
}

pub fn prepare(path: &Path) -> Result<(), String> {
    match validate(path, Storage::SeparateState) {
        Ok(()) => Ok(()),
        Err(validation_error) => {
            let empty = DocumentMut::new();
            match port_registry::replace(
                path,
                port_registry::RegistrySecurity::DerivedState,
                &empty,
            ) {
                Ok(()) => {
                    eprintln!("event=route_state_rebuild result=discarded_invalid_state");
                    Ok(())
                }
                Err(replacement_error) => Err(format!(
                    "{validation_error}; cannot rebuild disposable derived route state: {replacement_error}"
                )),
            }
        }
    }
}

pub fn load(path: &Path, hostname: &str, storage: Storage) -> Result<Option<CachedRoute>, String> {
    let document = read_for_use(path, storage)?;
    cached_route(&document, hostname)
}

fn cached_route(document: &DocumentMut, hostname: &str) -> Result<Option<CachedRoute>, String> {
    let Some(route) = document
        .get(TABLE)
        .and_then(|item| item.as_table())
        .and_then(|routes| routes.get(hostname))
        .and_then(|item| item.as_table())
    else {
        return Ok(None);
    };
    Ok(Some(CachedRoute {
        project: route
            .get("project")
            .and_then(|item| item.as_str())
            .expect("validated route project is a string")
            .to_string(),
        role: route
            .get("role")
            .and_then(|item| item.as_str())
            .expect("validated route role is a string")
            .to_string(),
        certificate_fingerprint: route
            .get("certificate_fingerprint")
            .and_then(|item| item.as_str())
            .expect("validated route fingerprint is a string")
            .to_string(),
    }))
}

fn read_for_use(path: &Path, storage: Storage) -> Result<DocumentMut, String> {
    let document = port_registry::read(path, storage.security())?;
    match validate_document(&document, storage) {
        Ok(()) => Ok(document),
        Err(error) if storage == Storage::SeparateState => Err(error),
        Err(_) => port_registry::update(path, storage.security(), |current| {
            if discard_invalid_combined_routes(current, storage) {
                eprintln!("event=route_state_rebuild result=discarded_invalid_development_cache");
            }
            Ok(current.clone())
        }),
    }
}

fn discard_invalid_combined_routes(document: &mut DocumentMut, storage: Storage) -> bool {
    if storage == Storage::CombinedRegistry && validate_document(document, storage).is_err() {
        document.as_table_mut().remove(TABLE);
        return true;
    }
    false
}

pub fn store(
    path: &Path,
    storage: Storage,
    hostname: &str,
    project: &str,
    role: &str,
    certificate_fingerprint: &str,
) -> Result<(), String> {
    if storage == Storage::SeparateState {
        validate_route_fields(hostname, project, role, certificate_fingerprint)?;
    }
    let verified_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX);

    port_registry::update(path, storage.security(), |document| {
        discard_invalid_combined_routes(document, storage);
        if !document.contains_table(TABLE) {
            document[TABLE] = toml_edit::table();
        }
        let routes = document[TABLE]
            .as_table_mut()
            .expect("the discovered route table was just created");
        let target_len = routes
            .len()
            .saturating_add(usize::from(!routes.contains_key(hostname)));
        let remove_count = target_len.saturating_sub(MAX_CACHED_ROUTES);
        if remove_count > 0 {
            let mut oldest = routes
                .iter()
                .filter(|(candidate, _)| *candidate != hostname)
                .map(|(candidate, item)| {
                    (
                        item.as_table()
                            .and_then(|route| route.get("last_verified_unix"))
                            .and_then(|item| item.as_integer())
                            .unwrap_or(i64::MIN),
                        candidate.to_string(),
                    )
                })
                .collect::<Vec<_>>();
            oldest.sort();
            for (_, candidate) in oldest.into_iter().take(remove_count) {
                routes.remove(&candidate);
            }
        }
        document[TABLE][hostname] = toml_edit::table();
        document[TABLE][hostname]["project"] = value(project);
        document[TABLE][hostname]["role"] = value(role);
        document[TABLE][hostname]["certificate_fingerprint"] = value(certificate_fingerprint);
        document[TABLE][hostname]["last_verified_unix"] = value(verified_at);
        validate_document(document, storage)
    })
}

pub fn remove(path: &Path, storage: Storage, hostname: &str) -> Result<(), String> {
    port_registry::update(path, storage.security(), |document| {
        discard_invalid_combined_routes(document, storage);
        if let Some(routes) = document.get_mut(TABLE).and_then(|item| item.as_table_mut()) {
            routes.remove(hostname);
        }
        validate_document(document, storage)
    })
}

pub fn retain_targets(
    path: &Path,
    storage: Storage,
    targets: &BTreeMap<String, (String, String)>,
) -> Result<(), String> {
    port_registry::update(path, storage.security(), |document| {
        discard_invalid_combined_routes(document, storage);
        if let Some(routes) = document.get_mut(TABLE).and_then(|item| item.as_table_mut()) {
            routes.retain(|hostname, item| {
                let Some((project, role)) = targets.get(hostname) else {
                    return false;
                };
                item.as_table().is_some_and(|route| {
                    route.get("project").and_then(|item| item.as_str()) == Some(project)
                        && route.get("role").and_then(|item| item.as_str()) == Some(role)
                })
            });
        }
        validate_document(document, storage)
    })
}

pub fn remove_for_registration(document: &mut DocumentMut, project: &str, role: Option<&str>) {
    discard_invalid_combined_routes(document, Storage::CombinedRegistry);
    let Some(routes) = document.get_mut(TABLE).and_then(|item| item.as_table_mut()) else {
        return;
    };
    let hostnames: Vec<String> = routes
        .iter()
        .filter_map(|(hostname, item)| {
            let route = item.as_table()?;
            let same_project = route.get("project")?.as_str()? == project;
            let route_role = route.get("role")?.as_str()?;
            let same_role = role.is_none_or(|expected| route_role == expected);
            (same_project && same_role).then(|| hostname.to_string())
        })
        .collect();

    for hostname in hostnames {
        routes.remove(&hostname);
    }
}

pub fn print(path: &Path, storage: Storage) -> Result<(), String> {
    let document = read_for_use(path, storage)?;
    let Some(routes) = document.get(TABLE).and_then(|item| item.as_table()) else {
        eprintln!("No discovered TLS routes.");
        return Ok(());
    };

    let mut entries: Vec<_> = routes
        .iter()
        .filter_map(|(hostname, item)| {
            let route = item.as_table()?;
            Some((
                hostname,
                route.get("project")?.as_str()?,
                route.get("role")?.as_str()?,
                route.get("certificate_fingerprint")?.as_str()?,
            ))
        })
        .collect();
    entries.sort_by_key(|(hostname, _, _, _)| *hostname);

    if entries.is_empty() {
        eprintln!("No discovered TLS routes.");
        return Ok(());
    }

    for (hostname, project, role, fingerprint) in entries {
        println!("{hostname} -> {project} ({role}) [{fingerprint}]");
    }
    Ok(())
}

pub fn write_new(path: &Path, document: &DocumentMut) -> Result<(), String> {
    validate_document(document, Storage::SeparateState)?;
    port_registry::write_new(
        path,
        port_registry::RegistrySecurity::DerivedState,
        document,
    )
}

fn validate_document(document: &DocumentMut, storage: Storage) -> Result<(), String> {
    let Some(routes) = document.get(TABLE) else {
        return Ok(());
    };
    let routes = routes
        .as_table()
        .ok_or_else(|| format!("[{TABLE}] must be a table"))?;
    if routes.len() > MAX_CACHED_ROUTES {
        return Err(format!(
            "derived route state contains {} routes, exceeding the limit of {MAX_CACHED_ROUTES}",
            routes.len()
        ));
    }
    for (hostname, item) in routes {
        let route = item
            .as_table()
            .ok_or_else(|| format!("derived route {hostname:?} must be a table"))?;
        if storage == Storage::SeparateState {
            for (key, _) in route {
                if !matches!(
                    key,
                    "project" | "role" | "certificate_fingerprint" | "last_verified_unix"
                ) {
                    return Err(format!(
                        "derived route {hostname:?} contains unknown key {key:?}"
                    ));
                }
            }
        }
        let project = route
            .get("project")
            .and_then(|item| item.as_str())
            .ok_or_else(|| format!("derived route {hostname:?} requires a string project"))?;
        let role = route
            .get("role")
            .and_then(|item| item.as_str())
            .ok_or_else(|| format!("derived route {hostname:?} requires a string role"))?;
        let fingerprint = route
            .get("certificate_fingerprint")
            .and_then(|item| item.as_str())
            .ok_or_else(|| {
                format!("derived route {hostname:?} requires a string certificate_fingerprint")
            })?;
        if route
            .get("last_verified_unix")
            .and_then(|item| item.as_integer())
            .is_none()
        {
            return Err(format!(
                "derived route {hostname:?} requires an integer last_verified_unix"
            ));
        }
        if storage == Storage::SeparateState {
            validate_route_fields(hostname, project, role, fingerprint)?;
        }
    }
    Ok(())
}

fn validate_route_fields(
    hostname: &str,
    project: &str,
    role: &str,
    certificate_fingerprint: &str,
) -> Result<(), String> {
    let normalized = tls_client_hello::normalize_hostname(hostname)
        .map_err(|_| format!("derived route hostname {hostname:?} is invalid"))?;
    if normalized != hostname {
        return Err(format!(
            "derived route hostname {hostname:?} must be normalized as {normalized:?}"
        ));
    }
    port_registry::validate_workload_id(project)
        .map_err(|error| format!("derived route Workload {project:?} is invalid: {error}"))?;
    port_registry::validate_role(role)
        .map_err(|error| format!("derived route role {role:?} is invalid: {error}"))?;
    if certificate_fingerprint.is_empty()
        || certificate_fingerprint.len() > MAX_FINGERPRINT_LENGTH
        || !certificate_fingerprint.is_ascii()
    {
        return Err(format!(
            "derived route certificate fingerprint must contain 1 through {MAX_FINGERPRINT_LENGTH} ASCII characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CACHED_ROUTES, Storage, load, prepare, remove, remove_for_registration, store,
    };
    use crate::{read_config, update_config};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::{TempDir, tempdir_in};
    use toml_edit::value;

    fn tempdir() -> std::io::Result<TempDir> {
        #[cfg(unix)]
        let root = Path::new("/tmp").canonicalize()?;
        #[cfg(not(unix))]
        let root = std::env::temp_dir().canonicalize()?;
        tempdir_in(root)
    }

    #[test]
    fn persists_and_loads_a_discovered_route_without_changing_ports() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        update_config(&path, |document| {
            document["ports"]["/project"]["https"] = value(4401);
        });

        store(
            &path,
            Storage::CombinedRegistry,
            "www.example.com",
            "/project",
            "https",
            "AA:BB",
        )
        .unwrap();

        let route = load(&path, "www.example.com", Storage::CombinedRegistry)
            .unwrap()
            .unwrap();
        assert_eq!(route.project, "/project");
        assert_eq!(route.role, "https");
        assert_eq!(route.certificate_fingerprint, "AA:BB");
        assert_eq!(
            read_config(&path)["ports"]["/project"]["https"].as_integer(),
            Some(4401)
        );
    }

    #[test]
    fn malformed_combined_route_state_is_discarded_without_changing_ports() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        update_config(&path, |document| {
            document["ports"]["/project"]["https"] = value(4401);
            document["discovered_routes"]["broken.example.com"] = toml_edit::table();
            document["discovered_routes"]["broken.example.com"]["project"] = value("/project");
            document["discovered_routes"]["broken.example.com"]["role"] = value(17);
            document["discovered_routes"]["broken.example.com"]["certificate_fingerprint"] =
                value("AA:BB");
            document["discovered_routes"]["broken.example.com"]["last_verified_unix"] = value(1);
        });

        assert!(
            load(&path, "broken.example.com", Storage::CombinedRegistry)
                .unwrap()
                .is_none()
        );

        let repaired = read_config(&path);
        assert_eq!(
            repaired["ports"]["/project"]["https"].as_integer(),
            Some(4401)
        );
        assert!(repaired.get("discovered_routes").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_private_route_state_is_discarded_without_weakening_permissions() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("routes.toml");
        fs::write(&path, "not valid TOML = [").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        prepare(&path).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn removing_a_registration_removes_only_its_derived_routes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        store(
            &path,
            Storage::CombinedRegistry,
            "one.example.com",
            "/one",
            "https",
            "11",
        )
        .unwrap();
        store(
            &path,
            Storage::CombinedRegistry,
            "two.example.com",
            "/two",
            "https",
            "22",
        )
        .unwrap();

        update_config(&path, |document| {
            remove_for_registration(document, "/one", Some("https"));
        });

        assert!(
            load(&path, "one.example.com", Storage::CombinedRegistry)
                .unwrap()
                .is_none()
        );
        assert!(
            load(&path, "two.example.com", Storage::CombinedRegistry)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn removes_one_hostname() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        store(
            &path,
            Storage::CombinedRegistry,
            "one.example.com",
            "/one",
            "https",
            "11",
        )
        .unwrap();
        store(
            &path,
            Storage::CombinedRegistry,
            "two.example.com",
            "/one",
            "https",
            "22",
        )
        .unwrap();

        remove(&path, Storage::CombinedRegistry, "one.example.com").unwrap();

        assert!(
            load(&path, "one.example.com", Storage::CombinedRegistry)
                .unwrap()
                .is_none()
        );
        assert!(
            load(&path, "two.example.com", Storage::CombinedRegistry)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn persistent_routes_evict_oldest_entries_at_the_fixed_bound() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        update_config(&path, |document| {
            document["discovered_routes"] = toml_edit::table();
            for index in 0..MAX_CACHED_ROUTES {
                let hostname = format!("host-{index}.example.com");
                document["discovered_routes"][&hostname] = toml_edit::table();
                document["discovered_routes"][&hostname]["project"] = value("/project");
                document["discovered_routes"][&hostname]["role"] = value("https");
                document["discovered_routes"][&hostname]["certificate_fingerprint"] = value("AA");
                document["discovered_routes"][&hostname]["last_verified_unix"] =
                    value(i64::try_from(index).unwrap());
            }
        });

        store(
            &path,
            Storage::CombinedRegistry,
            "newest.example.com",
            "/project",
            "https",
            "BB",
        )
        .unwrap();

        let document = read_config(&path);
        let routes = document["discovered_routes"].as_table().unwrap();
        assert_eq!(routes.len(), MAX_CACHED_ROUTES);
        assert!(!routes.contains_key("host-0.example.com"));
        assert!(routes.contains_key("newest.example.com"));
    }
}
