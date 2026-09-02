use crate::{read_config, update_config};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use toml_edit::{DocumentMut, value};

const TABLE: &str = "discovered_routes";
const MAX_CACHED_ROUTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedRoute {
    pub project: String,
    pub role: String,
    pub certificate_fingerprint: String,
}

pub fn load(path: &Path, hostname: &str) -> Option<CachedRoute> {
    let document = read_config(path);
    let route = document.get(TABLE)?.as_table()?.get(hostname)?.as_table()?;
    Some(CachedRoute {
        project: route.get("project")?.as_str()?.to_string(),
        role: route.get("role")?.as_str()?.to_string(),
        certificate_fingerprint: route.get("certificate_fingerprint")?.as_str()?.to_string(),
    })
}

pub fn store(
    path: &Path,
    hostname: &str,
    project: &str,
    role: &str,
    certificate_fingerprint: &str,
) {
    let verified_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    update_config(path, |document| {
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
    });
}

pub fn remove(path: &Path, hostname: &str) {
    update_config(path, |document| {
        if let Some(routes) = document.get_mut(TABLE).and_then(|item| item.as_table_mut()) {
            routes.remove(hostname);
        }
    });
}

pub fn remove_for_registration(document: &mut DocumentMut, project: &str, role: Option<&str>) {
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

pub fn print(path: &Path) {
    let document = read_config(path);
    let Some(routes) = document.get(TABLE).and_then(|item| item.as_table()) else {
        eprintln!("No discovered TLS routes.");
        return;
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
        return;
    }

    for (hostname, project, role, fingerprint) in entries {
        println!("{hostname} -> {project} ({role}) [{fingerprint}]");
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CACHED_ROUTES, load, remove, remove_for_registration, store};
    use crate::{read_config, update_config};
    use tempfile::tempdir;
    use toml_edit::value;

    #[test]
    fn persists_and_loads_a_discovered_route_without_changing_ports() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        update_config(&path, |document| {
            document["ports"]["/project"]["https"] = value(4401);
        });

        store(&path, "www.example.com", "/project", "https", "AA:BB");

        let route = load(&path, "www.example.com").unwrap();
        assert_eq!(route.project, "/project");
        assert_eq!(route.role, "https");
        assert_eq!(route.certificate_fingerprint, "AA:BB");
        assert_eq!(
            read_config(&path)["ports"]["/project"]["https"].as_integer(),
            Some(4401)
        );
    }

    #[test]
    fn removing_a_registration_removes_only_its_derived_routes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        store(&path, "one.example.com", "/one", "https", "11");
        store(&path, "two.example.com", "/two", "https", "22");

        update_config(&path, |document| {
            remove_for_registration(document, "/one", Some("https"));
        });

        assert!(load(&path, "one.example.com").is_none());
        assert!(load(&path, "two.example.com").is_some());
    }

    #[test]
    fn removes_one_hostname() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ports.toml");
        store(&path, "one.example.com", "/one", "https", "11");
        store(&path, "two.example.com", "/one", "https", "22");

        remove(&path, "one.example.com");

        assert!(load(&path, "one.example.com").is_none());
        assert!(load(&path, "two.example.com").is_some());
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

        store(&path, "newest.example.com", "/project", "https", "BB");

        let document = read_config(&path);
        let routes = document["discovered_routes"].as_table().unwrap();
        assert_eq!(routes.len(), MAX_CACHED_ROUTES);
        assert!(!routes.contains_key("host-0.example.com"));
        assert!(routes.contains_key("newest.example.com"));
    }
}
