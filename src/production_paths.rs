use crate::{port_registry, route_cache};
use std::env;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use toml_edit::DocumentMut;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

const DEFAULT_PORT_REGISTRY: &str = "/var/lib/phx-port/ports.toml";
const DEFAULT_RUNTIME_ROOT: &str = "/run/phx-port";
const MAX_INGRESS_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentOwner {
    Root,
    EffectiveUser,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionPaths {
    pub port_registry: PathBuf,
    pub route_cache: PathBuf,
    pub runtime_root: PathBuf,
}

impl ProductionPaths {
    pub fn from_environment() -> Result<Self, String> {
        let port_registry = absolute_environment_path("PHX_PORT_CONFIG")?
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PORT_REGISTRY));
        let state_directory = port_registry.parent().ok_or_else(|| {
            format!(
                "production Port Registry path must have a parent: {}",
                port_registry.display()
            )
        })?;
        let route_cache = state_directory.join("routes.toml");
        if route_cache == port_registry {
            return Err(
                "production Port Registry path must be distinct from derived routes.toml"
                    .to_string(),
            );
        }
        let runtime_root = absolute_environment_path("PHX_PORT_RUNTIME_DIR")?
            .unwrap_or_else(|| PathBuf::from(DEFAULT_RUNTIME_ROOT));

        Ok(Self {
            port_registry,
            route_cache,
            runtime_root,
        })
    }

    pub fn control_socket(&self) -> PathBuf {
        self.runtime_root.join("control").join("control.sock")
    }

    pub fn validate_intent_separation(&self, ingress_config: &Path) -> Result<(), String> {
        let ingress_config = absolute_path(ingress_config, "ingress config")?;
        if ingress_config == self.port_registry || ingress_config == self.route_cache {
            return Err(
                "root-owned ingress intent, stable assignments, and derived route state must use distinct files"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_paths(false)
    }

    pub fn prepare_for_startup(&self) -> Result<(), String> {
        self.validate_paths(true)
    }

    fn validate_paths(&self, repair_derived_state: bool) -> Result<(), String> {
        let state_directory = self
            .port_registry
            .parent()
            .expect("resolved production registry has a parent");
        if state_directory == self.runtime_root {
            return Err("production state directory and runtime root must be distinct".to_string());
        }
        port_registry::read_logical_assignments(&self.port_registry)?;
        if repair_derived_state {
            route_cache::prepare(&self.route_cache)?;
        } else {
            route_cache::validate(&self.route_cache, route_cache::Storage::SeparateState)?;
        }
        validate_runtime_root(&self.runtime_root)?;
        validate_optional_handoff_directory(&self.runtime_root.join("handoff"))
    }

    #[cfg(unix)]
    pub fn ensure_control_directory(&self) -> Result<PathBuf, String> {
        validate_runtime_root(&self.runtime_root)?;
        let directory = self.runtime_root.join("control");
        ensure_owned_directory(&directory, "production control directory", 0o750)?;
        Ok(directory)
    }
}

#[cfg(unix)]
pub fn ensure_owned_directory(path: &Path, description: &str, mode: u32) -> Result<(), String> {
    let absolute = absolute_path(path, description)?;
    ensure_directory_chain(&absolute, description, mode)?;
    validate_owned_directory(&absolute, description, &[mode])
}

#[cfg(not(unix))]
pub fn ensure_owned_directory(path: &Path, description: &str, _mode: u32) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create {description} {}: {error}", path.display()))
}

pub fn read_ingress_intent(path: &Path, owner: IntentOwner) -> Result<String, String> {
    let absolute = absolute_path(path, "ingress config")?;
    let parent = absolute
        .parent()
        .ok_or_else(|| "ingress config path must have a parent directory".to_string())?;
    validate_intent_ancestors(parent, owner)?;

    reject_symlink(&absolute, "ingress config")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options
        .open(&absolute)
        .map_err(|error| format!("cannot open ingress config {}: {error}", absolute.display()))?;
    validate_intent_file(&file, &absolute, owner)?;

    let mut content = Vec::new();
    (&file)
        .take(MAX_INGRESS_CONFIG_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|error| format!("cannot read ingress config {}: {error}", absolute.display()))?;
    if content.len() as u64 > MAX_INGRESS_CONFIG_BYTES {
        return Err(format!(
            "ingress config {} exceeds the {MAX_INGRESS_CONFIG_BYTES} byte limit",
            absolute.display()
        ));
    }
    String::from_utf8(content)
        .map_err(|_| format!("ingress config {} must be valid UTF-8", absolute.display()))
}

pub struct MigrationResult {
    pub port_registry: PathBuf,
    pub route_cache: PathBuf,
}

pub fn migrate_combined_registry(from: &Path, output: &Path) -> Result<MigrationResult, String> {
    let source = port_registry::read_existing_logical_registry(from)?;
    if output.as_os_str().is_empty() {
        return Err("migration output directory must not be empty".to_string());
    }
    let output = absolute_path(output, "migration output")?;
    reject_existing(&output, "migration output")?;
    let staging = create_migration_staging(&output)?;

    let staged_ports = staging.join("ports.toml");
    let staged_routes = staging.join("routes.toml");
    let mut ports = DocumentMut::new();
    ports["ports"] = source
        .get("ports")
        .cloned()
        .unwrap_or_else(toml_edit::table);
    let mut routes = DocumentMut::new();
    if let Some(discovered_routes) = source.get("discovered_routes") {
        routes["discovered_routes"] = discovered_routes.clone();
    }

    if let Err(error) = route_cache::write_new(&staged_routes, &routes) {
        remove_migration_output(&staging);
        return Err(error);
    }
    if let Err(error) = port_registry::write_new(
        &staged_ports,
        port_registry::RegistrySecurity::LogicalWorkload,
        &ports,
    ) {
        remove_migration_output(&staging);
        return Err(error);
    }
    if let Err(error) = publish_migration_output(&staging, &output) {
        remove_migration_output(&staging);
        return Err(error);
    }

    Ok(MigrationResult {
        port_registry: output.join("ports.toml"),
        route_cache: output.join("routes.toml"),
    })
}

fn absolute_environment_path(name: &str) -> Result<Option<PathBuf>, String> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(format!(
            "{name} must not be empty in the public Hosting Profile"
        ));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!(
            "{name} must be an absolute path in the public Hosting Profile: {}",
            path.display()
        ));
    }
    normalize_absolute_path(&path, name).map(Some)
}

fn absolute_path(path: &Path, description: &str) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| format!("cannot resolve {description} path: {error}"))?
    };
    normalize_absolute_path(&absolute, description)
}

fn normalize_absolute_path(path: &Path, description: &str) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "{description} path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

#[cfg(unix)]
fn validate_intent_ancestors(path: &Path, owner: IntentOwner) -> Result<(), String> {
    let expected_uid = match owner {
        IntentOwner::Root => 0,
        IntentOwner::EffectiveUser => nix::unistd::geteuid().as_raw(),
    };
    validate_directory_chain(
        path,
        "ingress config",
        expected_uid,
        owner == IntentOwner::Root,
    )
}

#[cfg(not(unix))]
fn validate_intent_ancestors(_path: &Path, _owner: IntentOwner) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_intent_file(file: &File, path: &Path, owner: IntentOwner) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect ingress config {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "ingress config {} must be a regular file",
            path.display()
        ));
    }
    let expected_uid = match owner {
        IntentOwner::Root => 0,
        IntentOwner::EffectiveUser => nix::unistd::geteuid().as_raw(),
    };
    if metadata.uid() != expected_uid {
        let requirement = match owner {
            IntentOwner::Root => "UID 0",
            IntentOwner::EffectiveUser => "the effective user",
        };
        return Err(format!(
            "ingress config {} must be owned by {requirement}",
            path.display()
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "ingress config {} must not be writable by group or other users, got mode {mode:04o}",
            path.display()
        ));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "ingress config {} must have exactly one filesystem link",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_intent_file(file: &File, path: &Path, _owner: IntentOwner) -> Result<(), String> {
    if !file
        .metadata()
        .map_err(|error| format!("cannot inspect ingress config {}: {error}", path.display()))?
        .is_file()
    {
        return Err(format!(
            "ingress config {} must be a regular file",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_runtime_root(path: &Path) -> Result<(), String> {
    validate_owned_directory(path, "production runtime root", &[0o700, 0o750])
}

#[cfg(not(unix))]
fn validate_runtime_root(_path: &Path) -> Result<(), String> {
    Err("the public Hosting Profile requires Unix runtime path security".to_string())
}

#[cfg(unix)]
fn validate_optional_handoff_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_owned_directory(path, "production handoff directory", &[0o700]),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect production handoff directory {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn validate_optional_handoff_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_owned_directory(
    path: &Path,
    description: &str,
    allowed_modes: &[u32],
) -> Result<(), String> {
    let absolute = absolute_path(path, description)?;
    validate_directory_chain(
        &absolute,
        description,
        nix::unistd::geteuid().as_raw(),
        false,
    )?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        format!(
            "cannot inspect {description} {}: {error}",
            absolute.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symbolic link for {description}: {}",
            absolute.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{description} {} must be a directory",
            absolute.display()
        ));
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(format!(
            "{description} {} must be owned by effective UID {}",
            absolute.display(),
            nix::unistd::geteuid().as_raw()
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if !allowed_modes.contains(&mode) {
        let expected = allowed_modes
            .iter()
            .map(|mode| format!("{mode:04o}"))
            .collect::<Vec<_>>()
            .join(" or ");
        return Err(format!(
            "{description} {} must have mode {expected}, got {mode:04o}",
            absolute.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_directory_chain(
    path: &Path,
    description: &str,
    expected_uid: u32,
    root_only: bool,
) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => {
                current.push(Path::new(std::path::MAIN_SEPARATOR_STR));
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "{description} path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Normal(part) => current.push(part),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "cannot inspect {description} path component {}: {error}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing symbolic link in {description} path: {}",
                current.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "{description} path component {} is not a directory",
                current.display()
            ));
        }
        let owner = metadata.uid();
        let owner_allowed = owner == 0 || (!root_only && owner == expected_uid);
        if !owner_allowed {
            return Err(format!(
                "{description} path component {} is owned by unexpected UID {owner}",
                current.display()
            ));
        }
        let mode = metadata.mode() & 0o7777;
        let root_owned_sticky_directory = owner == 0 && mode & 0o1000 != 0;
        if mode & 0o022 != 0 && !root_owned_sticky_directory {
            return Err(format!(
                "{description} path component {} is writable by group or other users",
                current.display()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_directory_chain(path: &Path, description: &str, final_mode: u32) -> Result<(), String> {
    let expected_uid = nix::unistd::geteuid().as_raw();
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => {
                current.push(Path::new(std::path::MAIN_SEPARATOR_STR));
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "{description} path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Normal(part) => current.push(part),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                validate_ensure_directory_component(&current, description, expected_uid, &metadata)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mode = if current == path { final_mode } else { 0o700 };
                let mut builder = fs::DirBuilder::new();
                builder.mode(mode);
                match builder.create(&current) {
                    Ok(()) => set_directory_mode_no_follow(&current, description, mode)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(format!(
                            "cannot create {description} path component {}: {error}",
                            current.display()
                        ));
                    }
                }
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    format!(
                        "cannot inspect newly created {description} path component {}: {error}",
                        current.display()
                    )
                })?;
                validate_ensure_directory_component(
                    &current,
                    description,
                    expected_uid,
                    &metadata,
                )?;
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect {description} path component {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_directory_mode_no_follow(path: &Path, description: &str, mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        format!(
            "cannot open newly created {description} path component {} without following links: {error}",
            path.display()
        )
    })?;
    if unsafe { nix::libc::fchmod(directory.as_raw_fd(), mode as nix::libc::mode_t) } == -1 {
        return Err(format!(
            "cannot set {description} path component {} to mode {mode:04o}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_ensure_directory_component(
    path: &Path,
    description: &str,
    expected_uid: u32,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symbolic link in {description} path: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{description} path component {} is not a directory",
            path.display()
        ));
    }
    let owner = metadata.uid();
    if owner != 0 && owner != expected_uid {
        return Err(format!(
            "{description} path component {} is owned by unexpected UID {owner}",
            path.display()
        ));
    }
    let mode = metadata.mode() & 0o7777;
    let root_owned_sticky_directory = owner == 0 && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !root_owned_sticky_directory {
        return Err(format!(
            "{description} path component {} is writable by group or other users",
            path.display()
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path, description: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "refusing symbolic link for {description}: {}",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect {description} {}: {error}",
            path.display()
        )),
    }
}

fn reject_existing(path: &Path, description: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "refusing to overwrite existing {description}: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect {description} {}: {error}",
            path.display()
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn path_c_string(path: &Path, description: &str) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{description} path contains a NUL byte: {}", path.display()))
}

#[cfg(target_os = "linux")]
fn publish_migration_output(staging: &Path, output: &Path) -> Result<(), String> {
    let staging_c = path_c_string(staging, "migration staging")?;
    let output_c = path_c_string(output, "migration output")?;
    // Both C strings remain live for the syscall, and staging/output are on one filesystem.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_renameat2,
            nix::libc::AT_FDCWD,
            staging_c.as_ptr(),
            nix::libc::AT_FDCWD,
            output_c.as_ptr(),
            nix::libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    let unsupported = matches!(
        error.raw_os_error(),
        Some(nix::libc::ENOSYS) | Some(nix::libc::EINVAL) | Some(nix::libc::EOPNOTSUPP)
    );
    migration_publication_error(output, error, unsupported)
}

#[cfg(target_os = "macos")]
fn publish_migration_output(staging: &Path, output: &Path) -> Result<(), String> {
    let staging_c = path_c_string(staging, "migration staging")?;
    let output_c = path_c_string(output, "migration output")?;
    // Both C strings remain live for renamex_np, and RENAME_EXCL prevents replacement.
    let result = unsafe {
        nix::libc::renamex_np(
            staging_c.as_ptr(),
            output_c.as_ptr(),
            nix::libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    let unsupported = matches!(
        error.raw_os_error(),
        Some(nix::libc::ENOSYS) | Some(nix::libc::EINVAL) | Some(nix::libc::EOPNOTSUPP)
    );
    migration_publication_error(output, error, unsupported)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn publish_migration_output(_staging: &Path, output: &Path) -> Result<(), String> {
    Err(format!(
        "atomic no-replace migration publication is unsupported on this platform: {}",
        output.display()
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn migration_publication_error(
    output: &Path,
    error: std::io::Error,
    unsupported: bool,
) -> Result<(), String> {
    if error.kind() == std::io::ErrorKind::AlreadyExists
        || error.raw_os_error() == Some(nix::libc::ENOTEMPTY)
    {
        return Err(format!(
            "refusing to overwrite existing migration output: {}",
            output.display()
        ));
    }
    if unsupported {
        return Err(format!(
            "atomic no-replace migration publication is unsupported for {}: {error}",
            output.display()
        ));
    }
    Err(format!(
        "cannot atomically publish migration output {}: {error}",
        output.display()
    ))
}

#[cfg(unix)]
fn create_migration_staging(output: &Path) -> Result<PathBuf, String> {
    let parent = output
        .parent()
        .ok_or_else(|| "migration output must have a parent directory".to_string())?;
    validate_directory_chain(
        parent,
        "migration output",
        nix::unistd::geteuid().as_raw(),
        false,
    )?;
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "migration output directory name must be valid UTF-8".to_string())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..16_u8 {
        let staging = parent.join(format!(
            ".{file_name}.phx-port-migrate-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&staging) {
            Ok(()) => return Ok(staging),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create migration staging directory {}: {error}",
                    staging.display()
                ));
            }
        }
    }
    Err("cannot allocate a unique migration staging directory".to_string())
}

#[cfg(not(unix))]
fn create_migration_staging(output: &Path) -> Result<PathBuf, String> {
    let parent = output
        .parent()
        .ok_or_else(|| "migration output must have a parent directory".to_string())?;
    let staging = parent.join(format!(".phx-port-migrate-{}", std::process::id()));
    fs::create_dir(&staging).map_err(|error| {
        format!(
            "cannot create migration staging directory {}: {error}",
            staging.display()
        )
    })?;
    Ok(staging)
}

fn remove_migration_output(output: &Path) {
    for name in [
        "routes.toml",
        "routes.toml.lock",
        "ports.toml",
        "ports.toml.lock",
    ] {
        let _ = fs::remove_file(output.join(name));
    }
    let _ = fs::remove_dir(output);
}

#[cfg(test)]
mod tests {
    use super::{
        IntentOwner, ProductionPaths, absolute_path, publish_migration_output, read_ingress_intent,
        reject_existing,
    };
    use crate::port_registry::{self, RegistrySecurity};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use tempfile::{TempDir, tempdir_in};

    fn tempdir() -> std::io::Result<TempDir> {
        #[cfg(unix)]
        let root = Path::new("/tmp").canonicalize()?;
        #[cfg(not(unix))]
        let root = std::env::temp_dir().canonicalize()?;
        tempdir_in(root)
    }

    #[cfg(unix)]
    #[test]
    fn ingress_intent_rejects_symlinks_and_writable_files() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("ingress.toml");
        fs::write(&config, "[ingress]\nmode = \"public\"\n").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(
            read_ingress_intent(&config, IntentOwner::EffectiveUser)
                .unwrap_err()
                .contains("must not be writable")
        );

        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let linked = directory.path().join("linked.toml");
        symlink(&config, &linked).unwrap();
        assert!(
            read_ingress_intent(&linked, IntentOwner::EffectiveUser)
                .unwrap_err()
                .contains("symbolic link")
        );
    }

    #[test]
    fn canonical_production_paths_are_separate() {
        let paths = ProductionPaths {
            port_registry: "/var/lib/phx-port/ports.toml".into(),
            route_cache: "/var/lib/phx-port/routes.toml".into(),
            runtime_root: "/run/phx-port".into(),
        };
        assert_ne!(paths.port_registry, paths.route_cache);
        assert_eq!(
            paths.control_socket(),
            PathBuf::from("/run/phx-port/control/control.sock")
        );
    }

    #[test]
    fn production_paths_are_lexically_normalized_before_comparison() {
        let raw = Path::new("/var/lib/phx-port/./ports.toml");
        let normalized = absolute_path(raw, "production Port Registry").unwrap();
        assert_eq!(
            normalized.as_os_str(),
            Path::new("/var/lib/phx-port/ports.toml").as_os_str()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn migration_publication_refuses_destination_created_after_precheck() {
        let directory = tempdir().unwrap();
        let staging = directory.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("ports.toml"), "[ports]\n").unwrap();
        let output = directory.path().join("output");

        reject_existing(&output, "migration output").unwrap();
        fs::create_dir(&output).unwrap();

        let error = publish_migration_output(&staging, &output).unwrap_err();
        assert!(error.contains("refusing to overwrite"));
        assert!(output.read_dir().unwrap().next().is_none());
        assert_eq!(
            fs::read_to_string(staging.join("ports.toml")).unwrap(),
            "[ports]\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_state_rejects_files_directly_under_the_filesystem_root() {
        let error = port_registry::read(
            Path::new("/phx-port-private-state-test.toml"),
            RegistrySecurity::LogicalWorkload,
        )
        .unwrap_err();
        assert!(error.contains("private directory below the filesystem root"));
    }

    #[cfg(unix)]
    #[test]
    fn public_runtime_rejects_handoff_symlinks_and_unsafe_control_modes() {
        let directory = tempdir().unwrap();
        let state = directory.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = directory.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750)).unwrap();
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&outside, runtime.join("handoff")).unwrap();
        let paths = ProductionPaths {
            port_registry: state.join("ports.toml"),
            route_cache: state.join("routes.toml"),
            runtime_root: runtime.clone(),
        };

        assert!(paths.validate().unwrap_err().contains("symbolic link"));

        fs::remove_file(runtime.join("handoff")).unwrap();
        fs::create_dir(runtime.join("handoff")).unwrap();
        fs::set_permissions(runtime.join("handoff"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(runtime.join("control")).unwrap();
        fs::set_permissions(runtime.join("control"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            paths
                .ensure_control_directory()
                .unwrap_err()
                .contains("must have mode 0750")
        );
    }
}
