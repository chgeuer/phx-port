use atomicwrites::{AllowOverwrite, AtomicFile};
use fs2::FileExt;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use toml_edit::{DocumentMut, value};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

const DEFAULT_ROLE: &str = "main";
const FIRST_ASSIGNED_PORT: i64 = 4001;
const LAST_ASSIGNED_PORT: i64 = u16::MAX as i64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrySecurity {
    Development,
    LogicalWorkload,
}

pub fn validate_workload_id(workload_id: &str) -> Result<(), String> {
    let bytes = workload_id.as_bytes();
    if !(1..=128).contains(&bytes.len()) {
        return Err("logical Workload ID must contain 1 through 128 ASCII characters".to_string());
    }
    if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(
            "logical Workload ID must start and end with a lowercase ASCII letter or digit"
                .to_string(),
        );
    }
    if !bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(
            "logical Workload ID may contain only lowercase ASCII letters, digits, '.', '_', and '-'"
                .to_string(),
        );
    }
    Ok(())
}

pub fn read(path: &Path, security: RegistrySecurity) -> Result<DocumentMut, String> {
    let path = prepare_path(path, security)?;
    let lock = open_lock(&path, security)?;
    FileExt::lock_shared(&lock)
        .map_err(|error| format!("cannot lock {} for reading: {error}", path.display()))?;
    let result = load(&path, security);
    unlock(lock, &path, result)
}

pub fn update<R>(
    path: &Path,
    security: RegistrySecurity,
    update: impl FnOnce(&mut DocumentMut) -> Result<R, String>,
) -> Result<R, String> {
    let path = prepare_path(path, security)?;
    let lock = open_lock(&path, security)?;
    FileExt::lock_exclusive(&lock)
        .map_err(|error| format!("cannot lock {} for update: {error}", path.display()))?;

    let result = (|| {
        let mut document = load(&path, security)?;
        let result = update(&mut document)?;
        if security == RegistrySecurity::LogicalWorkload {
            validate_logical_assignments(&document)?;
        }
        write_atomic(&path, &document, security)?;
        Ok(result)
    })();
    unlock(lock, &path, result)
}

pub fn allocate(
    path: &Path,
    workload: &str,
    role: &str,
    logical_workload: bool,
) -> Result<(i64, bool), String> {
    let security = if logical_workload {
        validate_workload_id(workload)?;
        RegistrySecurity::LogicalWorkload
    } else {
        RegistrySecurity::Development
    };

    update(path, security, |document| {
        ensure_ports_table(document);
        if let Some(port) = document["ports"]
            .as_table()
            .and_then(|ports| ports.get(workload))
            .and_then(|roles| roles.as_table())
            .and_then(|roles| roles.get(role))
            .and_then(|port| port.as_integer())
        {
            return Ok((port, false));
        }

        let port = next_port(document)?;
        if document["ports"]
            .as_table()
            .is_none_or(|ports| !ports.contains_key(workload))
        {
            document["ports"][workload] = toml_edit::table();
        }
        document["ports"][workload][role] = value(port);
        Ok((port, true))
    })
}

fn prepare_path(path: &Path, security: RegistrySecurity) -> Result<PathBuf, String> {
    if security == RegistrySecurity::Development {
        ensure_development_parent(path)?;
        return Ok(path.to_path_buf());
    }
    prepare_logical_registry_path(path)
}

fn ensure_development_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    Ok(())
}

fn prepare_logical_registry_path(path: &Path) -> Result<PathBuf, String> {
    if path.file_name().is_none() {
        return Err("logical Workload registry path must name a file".to_string());
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cannot resolve registry path: {error}"))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| "logical Workload registry path must have a parent directory".to_string())?;
    ensure_secure_directory_path(parent)?;
    Ok(absolute)
}

fn ensure_secure_directory_path(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    let components = path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "logical Workload registry path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Normal(part) => current.push(part),
        }
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => validate_directory(
                &current,
                &metadata,
                index == components.len().saturating_sub(1),
            )?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_directory(&current)?;
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    format!(
                        "cannot inspect newly created registry directory {}: {error}",
                        current.display()
                    )
                })?;
                validate_directory(
                    &current,
                    &metadata,
                    index == components.len().saturating_sub(1),
                )?;
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect registry directory {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "cannot create private registry directory {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "cannot create registry directory {}: {error}",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn validate_directory(
    path: &Path,
    metadata: &fs::Metadata,
    final_parent: bool,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symbolic link in logical Workload registry path: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "logical Workload registry path component is not a directory: {}",
            path.display()
        ));
    }

    let effective_uid = nix::unistd::geteuid().as_raw();
    let owner = metadata.uid();
    let mode = metadata.mode() & 0o7777;
    if final_parent {
        if owner != effective_uid {
            return Err(format!(
                "logical Workload registry directory {} must be owned by effective UID {}",
                path.display(),
                effective_uid
            ));
        }
        if mode != 0o700 {
            return Err(format!(
                "logical Workload registry directory {} must have mode 0700, got {mode:04o}",
                path.display()
            ));
        }
        return Ok(());
    }

    if owner != 0 && owner != effective_uid {
        return Err(format!(
            "registry path ancestor {} is owned by unexpected UID {owner}",
            path.display()
        ));
    }
    let root_owned_sticky_directory = owner == 0 && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !root_owned_sticky_directory {
        return Err(format!(
            "registry path ancestor {} is writable by group or other users",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory(
    path: &Path,
    metadata: &fs::Metadata,
    _final_parent: bool,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symbolic link in logical Workload registry path: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "logical Workload registry path component is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn open_lock(path: &Path, security: RegistrySecurity) -> Result<File, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("phx-ports.toml");
    let lock_path = path.with_file_name(format!("{file_name}.lock"));
    if security == RegistrySecurity::LogicalWorkload {
        reject_symlink(&lock_path, "registry lock")?;
    }

    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    if security == RegistrySecurity::LogicalWorkload {
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options
        .open(&lock_path)
        .map_err(|error| format!("cannot open registry lock {}: {error}", lock_path.display()))?;
    if security == RegistrySecurity::LogicalWorkload {
        validate_private_file(&file, &lock_path, "registry lock")?;
    }
    Ok(file)
}

fn load(path: &Path, security: RegistrySecurity) -> Result<DocumentMut, String> {
    let mut document = match read_content(path, security)? {
        Some(content) => content
            .parse::<DocumentMut>()
            .map_err(|error| format!("cannot parse {}: {error}", path.display()))?,
        None => "[ports]\n"
            .parse::<DocumentMut>()
            .expect("the empty registry document is valid TOML"),
    };

    if security == RegistrySecurity::LogicalWorkload
        && document.get("ports").is_some()
        && !document.contains_table("ports")
    {
        return Err("logical Workload registry [ports] value must be a table".to_string());
    }
    ensure_ports_table(&mut document);
    migrate_legacy_assignments(&mut document);
    if security == RegistrySecurity::LogicalWorkload {
        validate_logical_assignments(&document)?;
    }
    Ok(document)
}

fn read_content(path: &Path, security: RegistrySecurity) -> Result<Option<String>, String> {
    if security == RegistrySecurity::Development {
        return match fs::read_to_string(path) {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        };
    }

    reject_symlink(path, "logical Workload registry")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "cannot open logical Workload registry {}: {error}",
                path.display()
            ));
        }
    };
    validate_private_file(&file, path, "logical Workload registry")?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(Some(content))
}

fn reject_symlink(path: &Path, kind: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "refusing symbolic link for {kind}: {}",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect {kind} {}: {error}", path.display())),
    }
}

#[cfg(unix)]
fn validate_private_file(file: &File, path: &Path, kind: &str) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {kind} {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{kind} {} must be a regular file", path.display()));
    }
    let effective_uid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != effective_uid {
        return Err(format!(
            "{kind} {} must be owned by effective UID {}",
            path.display(),
            effective_uid
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if mode != 0o600 {
        return Err(format!(
            "{kind} {} must have mode 0600, got {mode:04o}",
            path.display()
        ));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "{kind} {} must have exactly one filesystem link",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file(file: &File, path: &Path, kind: &str) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {kind} {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{kind} {} must be a regular file", path.display()));
    }
    Ok(())
}

fn ensure_ports_table(document: &mut DocumentMut) {
    if !document.contains_table("ports") {
        document["ports"] = toml_edit::table();
    }
}

fn migrate_legacy_assignments(document: &mut DocumentMut) {
    let old_entries = document["ports"]
        .as_table()
        .map(|ports| {
            ports
                .iter()
                .filter_map(|(key, value)| value.as_integer().map(|port| (key.to_string(), port)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (workload, port) in old_entries {
        document["ports"][&workload] = toml_edit::table();
        document["ports"][&workload][DEFAULT_ROLE] = value(port);
    }
}

fn validate_logical_assignments(document: &DocumentMut) -> Result<(), String> {
    let ports = document
        .get("ports")
        .and_then(|ports| ports.as_table())
        .ok_or_else(|| "logical Workload registry must contain a [ports] table".to_string())?;
    let mut assignments = BTreeMap::new();
    for (workload, roles) in ports {
        validate_workload_id(workload)
            .map_err(|error| format!("invalid registry Workload {workload:?}: {error}"))?;
        let roles = roles.as_table().ok_or_else(|| {
            format!("registry Workload {workload:?} must contain a role-to-port table")
        })?;
        for (role, port) in roles {
            let port = port.as_integer().ok_or_else(|| {
                format!("registry assignment {workload:?}/{role:?} must be an integer")
            })?;
            if !(1..=LAST_ASSIGNED_PORT).contains(&port) {
                return Err(format!(
                    "registry assignment {workload:?}/{role:?} must be a TCP port from 1 through {LAST_ASSIGNED_PORT}, got {port}"
                ));
            }
            if let Some(previous) = assignments.insert(port, format!("{workload}/{role}")) {
                return Err(format!(
                    "registry port {port} is assigned to both {previous} and {workload}/{role}"
                ));
            }
        }
    }
    Ok(())
}

fn next_port(document: &DocumentMut) -> Result<i64, String> {
    let mut used = BTreeSet::new();
    if let Some(ports) = document["ports"].as_table() {
        for (_, roles) in ports {
            if let Some(roles) = roles.as_table() {
                for (_, port) in roles {
                    if let Some(port) = port.as_integer() {
                        used.insert(port);
                    }
                }
            }
        }
    }
    (FIRST_ASSIGNED_PORT..=LAST_ASSIGNED_PORT)
        .find(|port| !used.contains(port))
        .ok_or_else(|| "no unassigned TCP ports remain from 4001 through 65535".to_string())
}

fn write_atomic(
    path: &Path,
    document: &DocumentMut,
    security: RegistrySecurity,
) -> Result<(), String> {
    let content = document.to_string();
    AtomicFile::new(path, AllowOverwrite)
        .write(|file| {
            #[cfg(unix)]
            if security == RegistrySecurity::LogicalWorkload {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(content.as_bytes())
        })
        .map_err(|error| format!("cannot atomically write {}: {error}", path.display()))?;

    if security == RegistrySecurity::LogicalWorkload {
        reject_symlink(path, "logical Workload registry")?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        let file = options.open(path).map_err(|error| {
            format!(
                "cannot validate logical Workload registry {} after write: {error}",
                path.display()
            )
        })?;
        validate_private_file(&file, path, "logical Workload registry")?;
    }
    Ok(())
}

fn unlock<R>(lock: File, path: &Path, result: Result<R, String>) -> Result<R, String> {
    let unlock_result = FileExt::unlock(&lock)
        .map_err(|error| format!("cannot unlock {}: {error}", path.display()));
    drop(lock);
    match result {
        Err(error) => Err(error),
        Ok(value) => {
            unlock_result?;
            Ok(value)
        }
    }
}
