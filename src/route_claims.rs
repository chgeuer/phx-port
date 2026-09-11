use crate::{port_registry, route_pattern};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use toml_edit::{Array, DocumentMut, value};

pub const MAX_CLAIMS: usize = 1024;
pub const MAX_DISCOVERY_WORKLOADS: usize = 32;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Claims {
    pub routes: BTreeMap<String, BTreeSet<String>>,
    pub saturated_workloads: BTreeSet<String>,
}

impl Claims {
    pub fn add(&mut self, pattern: &str, workload: &str) {
        if self
            .routes
            .get(pattern)
            .is_some_and(|owners| owners.contains(workload))
        {
            return;
        }
        if self.routes.values().map(BTreeSet::len).sum::<usize>() >= MAX_CLAIMS {
            // Losing an unrecorded exact name must never expose it to a wildcard,
            // including after restart. Only removing this registration releases it.
            self.saturated_workloads.insert(workload.to_string());
            return;
        }
        self.routes
            .entry(pattern.to_string())
            .or_default()
            .insert(workload.to_string());
    }

    pub fn retain_registrations(&mut self, assignments: &port_registry::LogicalAssignments) {
        let registered =
            |workload: &String| assignments.contains_key(&(workload.clone(), "https".to_string()));
        self.routes.retain(|_, owners| {
            owners.retain(registered);
            !owners.is_empty()
        });
        self.saturated_workloads.retain(registered);
    }

    pub fn matching(&self, hostname: &str) -> Option<(&str, &BTreeSet<String>)> {
        self.routes
            .get_key_value(hostname)
            .or_else(|| {
                route_pattern::matching_wildcard(hostname)
                    .and_then(|pattern| self.routes.get_key_value(&pattern))
            })
            .map(|(pattern, owners)| (pattern.as_str(), owners))
    }

    pub fn conflict_count(&self) -> usize {
        self.routes
            .values()
            .filter(|owners| owners.len() > 1)
            .count()
    }
}

fn existed(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot inspect ownership claims: {error}")),
    }
}

pub fn load_until(
    path: &Path,
    deadline: Option<port_registry::AccessDeadline<'_>>,
) -> Result<Claims, String> {
    let existed = existed(path)?;
    let document = port_registry::read_until(
        path,
        port_registry::RegistrySecurity::DerivedState,
        deadline,
    )?;
    parse(&document, !existed)
}

pub fn load_existing_until(
    path: &Path,
    deadline: Option<port_registry::AccessDeadline<'_>>,
) -> Result<Claims, String> {
    let document = port_registry::read_until(
        path,
        port_registry::RegistrySecurity::DerivedState,
        deadline,
    )?;
    parse(&document, false)
}

pub fn update_until(
    path: &Path,
    deadline: Option<port_registry::AccessDeadline<'_>>,
    update: impl FnOnce(&mut Claims),
) -> Result<Claims, String> {
    update_with_creation(path, deadline, true, update)
}

pub fn update_existing_until(
    path: &Path,
    deadline: Option<port_registry::AccessDeadline<'_>>,
    update: impl FnOnce(&mut Claims),
) -> Result<Claims, String> {
    update_with_creation(path, deadline, false, update)
}

fn update_with_creation(
    path: &Path,
    deadline: Option<port_registry::AccessDeadline<'_>>,
    allow_create: bool,
    update: impl FnOnce(&mut Claims),
) -> Result<Claims, String> {
    let existed = existed(path)?;
    if !existed && !allow_create {
        return Err(
            "durable ownership claims are missing; restore them before discovery resumes".into(),
        );
    }
    port_registry::update_if_changed_until(
        path,
        port_registry::RegistrySecurity::DerivedState,
        deadline,
        |document| {
            let mut claims = parse(document, allow_create && !existed)?;
            let previous = claims.clone();
            update(&mut claims);
            let replacement = encode(&claims);
            parse(&replacement, false)?;
            let changed = !existed || claims != previous;
            if changed {
                *document = replacement;
            }
            Ok((claims, changed))
        },
    )
}

fn parse(document: &DocumentMut, allow_empty: bool) -> Result<Claims, String> {
    if allow_empty && document.as_table().is_empty() {
        return Ok(Claims::default());
    }
    if document.get("version").and_then(|item| item.as_integer()) != Some(1) {
        return Err(
            "ownership claims require version = 1; restore durable claims, do not discard them"
                .into(),
        );
    }
    for (key, _) in document.as_table() {
        if !matches!(key, "version" | "claims" | "saturated_workloads") {
            return Err(format!("unknown ownership claims key {key:?}"));
        }
    }
    let mut claims = Claims::default();
    let routes = document
        .get("claims")
        .and_then(|item| item.as_table())
        .ok_or_else(|| "ownership claims require a [claims] table".to_string())?;
    if routes.len() > MAX_CLAIMS {
        return Err("ownership claim capacity exceeded".into());
    }
    let mut count = 0;
    for (pattern, item) in routes {
        if route_pattern::normalize(pattern).map_err(|error| error.to_string())? != pattern {
            return Err("ownership claim patterns must be canonical".into());
        }
        let owners = parse_owners(item.as_array(), MAX_DISCOVERY_WORKLOADS)?;
        if owners.is_empty() {
            return Err("ownership claims must have at least one Workload".into());
        }
        count += owners.len();
        if count > MAX_CLAIMS {
            return Err("ownership claim capacity exceeded".into());
        }
        claims.routes.insert(pattern.to_string(), owners);
    }
    claims.saturated_workloads = parse_owners(
        document
            .get("saturated_workloads")
            .and_then(|item| item.as_array()),
        MAX_DISCOVERY_WORKLOADS,
    )?;
    Ok(claims)
}

fn parse_owners(array: Option<&Array>, limit: usize) -> Result<BTreeSet<String>, String> {
    let array = array.ok_or_else(|| "ownership Workloads must be an array".to_string())?;
    if array.len() > limit {
        return Err("ownership Workload capacity exceeded".into());
    }
    let mut owners = BTreeSet::new();
    for item in array {
        let owner = item
            .as_str()
            .ok_or_else(|| "ownership Workloads must be strings".to_string())?;
        port_registry::validate_workload_id(owner)?;
        if !owners.insert(owner.to_string()) {
            return Err("ownership Workloads must not be repeated".into());
        }
    }
    Ok(owners)
}

fn encode(claims: &Claims) -> DocumentMut {
    let mut document = DocumentMut::new();
    document["version"] = value(1);
    document["saturated_workloads"] = value(
        claims
            .saturated_workloads
            .iter()
            .map(String::as_str)
            .collect::<Array>(),
    );
    document["claims"] = toml_edit::table();
    for (pattern, owners) in &claims.routes {
        document["claims"][pattern] = value(owners.iter().map(String::as_str).collect::<Array>());
    }
    document
}

pub fn print(path: &Path) -> Result<(), String> {
    let claims = load_until(path, None)?;
    for (pattern, owners) in claims.routes {
        let state = if owners.len() == 1 {
            "requires verification"
        } else {
            "conflict"
        };
        println!(
            "{pattern} -> {} (https) [{state}; durable claim]",
            owners.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    if !claims.saturated_workloads.is_empty() {
        println!(
            "certificate_discovery blocked: claim_capacity_exhausted; remove saturated HTTPS registrations to release unrecorded claims"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn directory() -> tempfile::TempDir {
        let root = std::env::var_os("PHX_PORT_TEST_TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = tempfile::tempdir_in(root.canonicalize().unwrap()).unwrap();
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn exact_claims_and_conflicts_survive_reload_until_registration_removal() {
        let directory = directory();
        let path = directory.path().join("route-claims.toml");
        update_until(&path, None, |claims| {
            claims.add("*.example.test", "wild");
            claims.add("specific.example.test", "exact");
            claims.add("specific.example.test", "other");
        })
        .unwrap();
        let loaded = load_until(&path, None).unwrap();
        assert_eq!(loaded.matching("specific.example.test").unwrap().1.len(), 2);
        let assignments = port_registry::LogicalAssignments::from([
            (("wild".into(), "https".into()), 4101),
            (("exact".into(), "https".into()), 4102),
        ]);
        let claims = update_until(&path, None, |claims| {
            claims.retain_registrations(&assignments)
        })
        .unwrap();
        assert_eq!(
            claims.matching("specific.example.test").unwrap().1,
            &BTreeSet::from(["exact".into()])
        );
        assert_eq!(
            claims.matching("another.example.test").unwrap().0,
            "*.example.test"
        );
    }

    #[test]
    fn capacity_never_evicts_exact_claims_and_saturation_is_durable() {
        let directory = directory();
        let path = directory.path().join("route-claims.toml");
        update_until(&path, None, |claims| {
            for index in 0..MAX_CLAIMS {
                claims.add(&format!("exact-{index}.example.test"), "old");
            }
            claims.add("unrecorded.example.test", "overflow");
        })
        .unwrap();
        let claims = load_until(&path, None).unwrap();
        assert_eq!(claims.routes.len(), MAX_CLAIMS);
        assert!(claims.routes.contains_key("exact-0.example.test"));
        assert_eq!(
            claims.saturated_workloads,
            BTreeSet::from(["overflow".into()])
        );
        let assignments =
            port_registry::LogicalAssignments::from([(("old".into(), "https".into()), 4101)]);
        let claims = update_until(&path, None, |claims| {
            claims.retain_registrations(&assignments)
        })
        .unwrap();
        assert!(claims.saturated_workloads.is_empty());
        assert_eq!(claims.routes.len(), MAX_CLAIMS);
    }

    #[test]
    fn damaged_durable_state_is_never_discarded_or_rebuilt() {
        let directory = directory();
        let path = directory.path().join("route-claims.toml");
        update_until(&path, None, |claims| {
            claims.add("exact.example.test", "exact")
        })
        .unwrap();
        for invalid in ["", "not valid TOML [", "version = 99\n"] {
            fs::write(&path, invalid).unwrap();
            assert!(load_until(&path, None).is_err());
            assert!(
                update_until(&path, None, |claims| claims.add("*.example.test", "wild")).is_err()
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
        }
    }
}
