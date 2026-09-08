use atomicwrites::{AllowOverwrite, AtomicFile};
use fs2::FileExt;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use toml_edit::{DocumentMut, value};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

const DEFAULT_ROLE: &str = "main";
const FIRST_ASSIGNED_PORT: i64 = 4001;
const LAST_ASSIGNED_PORT: i64 = u16::MAX as i64;
const MAX_ROLE_LENGTH: usize = 128;
const MAX_PRIVATE_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DerivedIoCounts {
    pub reads: usize,
    pub writes: usize,
    pub route_entries_written: usize,
}

#[cfg(test)]
thread_local! {
    static DERIVED_IO_COUNTS: std::cell::Cell<DerivedIoCounts> = const {
        std::cell::Cell::new(DerivedIoCounts {
            reads: 0,
            writes: 0,
            route_entries_written: 0,
        })
    };
}

#[cfg(test)]
pub(crate) fn take_derived_io_counts() -> DerivedIoCounts {
    DERIVED_IO_COUNTS.with(std::cell::Cell::take)
}

pub type LogicalAssignments = BTreeMap<(String, String), u16>;

#[derive(Clone, Copy)]
pub(crate) struct AccessDeadline<'a> {
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
}

impl AccessDeadline<'_> {
    fn remaining(self) -> Result<Duration, String> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("registry operation cancelled during shutdown".to_string());
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| "registry operation timed out".to_string())
    }
}

fn lock_for_access(
    lock: &File,
    path: &Path,
    exclusive: bool,
    deadline: Option<AccessDeadline<'_>>,
) -> Result<(), String> {
    let Some(deadline) = deadline else {
        return if exclusive {
            FileExt::lock_exclusive(lock)
        } else {
            FileExt::lock_shared(lock)
        }
        .map_err(|error| format!("cannot lock {}: {error}", path.display()));
    };
    loop {
        let remaining = deadline.remaining()?;
        let result = if exclusive {
            FileExt::try_lock_exclusive(lock)
        } else {
            FileExt::try_lock_shared(lock)
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("cannot lock {}: {error}", path.display())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrySecurity {
    Development,
    LogicalWorkload,
    DerivedState,
}

impl RegistrySecurity {
    fn is_private(self) -> bool {
        self != Self::Development
    }

    fn description(self) -> &'static str {
        match self {
            Self::Development => "development registry",
            Self::LogicalWorkload => "logical Workload registry",
            Self::DerivedState => "derived route state",
        }
    }
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

pub fn validate_role(role: &str) -> Result<(), String> {
    if role.is_empty()
        || role.len() > MAX_ROLE_LENGTH
        || !role.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(format!(
            "role must contain 1 through {MAX_ROLE_LENGTH} lowercase ASCII letters, digits, '.', '_', or '-'"
        ));
    }
    Ok(())
}

pub fn read(path: &Path, security: RegistrySecurity) -> Result<DocumentMut, String> {
    read_until(path, security, None)
}

pub(crate) fn read_until(
    path: &Path,
    security: RegistrySecurity,
    deadline: Option<AccessDeadline<'_>>,
) -> Result<DocumentMut, String> {
    if let Some(deadline) = deadline {
        deadline.remaining()?;
    }
    let path = prepare_path(path, security)?;
    let lock = open_lock(&path, security)?;
    lock_for_access(&lock, &path, false, deadline)?;
    let result = load(&path, security);
    unlock(lock, &path, result)
}

pub(crate) fn read_logical_assignments_until(
    path: &Path,
    deadline: Option<AccessDeadline<'_>>,
) -> Result<LogicalAssignments, String> {
    let document = read_until(path, RegistrySecurity::LogicalWorkload, deadline)?;
    logical_assignments(&document)
}

pub fn read_existing_logical_registry(path: &Path) -> Result<DocumentMut, String> {
    let security = RegistrySecurity::LogicalWorkload;
    let path = prepare_existing_private_path(path, security.description())?;
    require_existing_private_file(&path, security.description())?;
    let lock = open_lock(&path, security)?;
    FileExt::lock_shared(&lock)
        .map_err(|error| format!("cannot lock {} for reading: {error}", path.display()))?;
    let result = load_required(&path, security);
    unlock(lock, &path, result)
}

pub fn update<R>(
    path: &Path,
    security: RegistrySecurity,
    update: impl FnOnce(&mut DocumentMut) -> Result<R, String>,
) -> Result<R, String> {
    update_until(path, security, None, update)
}

pub(crate) fn update_until<R>(
    path: &Path,
    security: RegistrySecurity,
    deadline: Option<AccessDeadline<'_>>,
    update: impl FnOnce(&mut DocumentMut) -> Result<R, String>,
) -> Result<R, String> {
    update_if_changed_until(path, security, deadline, |document| {
        update(document).map(|result| (result, true))
    })
}

pub(crate) fn update_if_changed_until<R>(
    path: &Path,
    security: RegistrySecurity,
    deadline: Option<AccessDeadline<'_>>,
    update: impl FnOnce(&mut DocumentMut) -> Result<(R, bool), String>,
) -> Result<R, String> {
    if let Some(deadline) = deadline {
        deadline.remaining()?;
    }
    let path = prepare_path(path, security)?;
    let lock = open_lock(&path, security)?;
    lock_for_access(&lock, &path, true, deadline)?;

    let result = (|| {
        let (mut document, migrated) = load_with_policy(&path, security, false)?;
        let (result, changed) = update(&mut document)?;
        if security == RegistrySecurity::LogicalWorkload {
            validate_logical_assignments(&document)?;
        }
        if let Some(deadline) = deadline {
            deadline.remaining()?;
        }
        if changed || migrated {
            write_atomic(&path, &document, security)?;
        }
        Ok(result)
    })();
    unlock(lock, &path, result)
}

pub fn write_new(
    path: &Path,
    security: RegistrySecurity,
    document: &DocumentMut,
) -> Result<(), String> {
    let path = prepare_path(path, security)?;
    reject_existing(&path, security.description())?;
    let lock = open_lock(&path, security)?;
    FileExt::lock_exclusive(&lock)
        .map_err(|error| format!("cannot lock {} for creation: {error}", path.display()))?;
    let result = (|| {
        reject_existing(&path, security.description())?;
        if security == RegistrySecurity::LogicalWorkload {
            validate_logical_assignments(document)?;
        }
        write_atomic(&path, document, security)
    })();
    unlock(lock, &path, result)
}

pub fn replace(
    path: &Path,
    security: RegistrySecurity,
    document: &DocumentMut,
) -> Result<(), String> {
    let path = prepare_path(path, security)?;
    let lock = open_lock(&path, security)?;
    FileExt::lock_exclusive(&lock)
        .map_err(|error| format!("cannot lock {} for replacement: {error}", path.display()))?;
    let result = (|| {
        if security.is_private() {
            validate_existing_private_file(&path, security.description())?;
        }
        if security == RegistrySecurity::LogicalWorkload {
            validate_logical_assignments(document)?;
        }
        write_atomic(&path, document, security)
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
        validate_role(role)?;
        RegistrySecurity::LogicalWorkload
    } else {
        RegistrySecurity::Development
    };

    let path = prepare_path(path, security)?;
    let lock = open_lock(&path, security)?;
    lock_for_access(&lock, &path, false, None)?;
    let result = (|| {
        let (document, migrated) = load_with_policy(&path, security, false)?;
        if !migrated && let Some(port) = assigned_port(&document, workload, role) {
            return Ok((port, false));
        }
        drop(document);

        // Release the shared lock before taking exclusive ownership, then recheck from disk.
        FileExt::unlock(&lock)
            .map_err(|error| format!("cannot unlock {}: {error}", path.display()))?;
        lock_for_access(&lock, &path, true, None)?;
        let (mut document, migrated) = load_with_policy(&path, security, false)?;
        let (port, created) = match assigned_port(&document, workload, role) {
            Some(port) => (port, false),
            None => {
                let port = next_port(&document)?;
                if document["ports"]
                    .as_table()
                    .is_none_or(|ports| !ports.contains_key(workload))
                {
                    document["ports"][workload] = toml_edit::table();
                }
                document["ports"][workload][role] = value(port);
                (port, true)
            }
        };
        if created || migrated {
            if security == RegistrySecurity::LogicalWorkload {
                validate_logical_assignments(&document)?;
            }
            write_atomic(&path, &document, security)?;
        }
        Ok((port, created))
    })();
    unlock(lock, &path, result)
}

fn assigned_port(document: &DocumentMut, workload: &str, role: &str) -> Option<i64> {
    document
        .get("ports")
        .and_then(|ports| ports.as_table())
        .and_then(|ports| ports.get(workload))
        .and_then(|roles| roles.as_table())
        .and_then(|roles| roles.get(role))
        .and_then(|port| port.as_integer())
}

fn prepare_path(path: &Path, security: RegistrySecurity) -> Result<PathBuf, String> {
    if !security.is_private() {
        ensure_development_parent(path)?;
        return Ok(path.to_path_buf());
    }
    prepare_private_path(path, security.description())
}

fn ensure_development_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    Ok(())
}

fn prepare_private_path(path: &Path, kind: &str) -> Result<PathBuf, String> {
    let absolute = resolve_private_path(path, kind)?;
    let parent = absolute
        .parent()
        .expect("resolved private state path has a parent");
    secure_directory_path(parent, kind, true)?;
    Ok(absolute)
}

fn prepare_existing_private_path(path: &Path, kind: &str) -> Result<PathBuf, String> {
    let absolute = resolve_private_path(path, kind)?;
    let parent = absolute
        .parent()
        .expect("resolved private state path has a parent");
    secure_directory_path(parent, kind, false)?;
    Ok(absolute)
}

fn resolve_private_path(path: &Path, kind: &str) -> Result<PathBuf, String> {
    if path.file_name().is_none() {
        return Err(format!("{kind} path must name a file"));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cannot resolve {kind} path: {error}"))?
            .join(path)
    };
    let absolute = normalize_private_path(&absolute, kind)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("{kind} path must have a parent directory"))?;
    if parent == Path::new(std::path::MAIN_SEPARATOR_STR) {
        return Err(format!(
            "{kind} path must use a private directory below the filesystem root"
        ));
    }
    Ok(absolute)
}

fn normalize_private_path(path: &Path, kind: &str) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "{kind} path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn secure_directory_path(path: &Path, kind: &str, create_missing: bool) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "{kind} path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Normal(part) => current.push(part),
        }
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => validate_directory(&current, &metadata, current == path, kind)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create_missing => {
                create_private_directory(&current, kind)?;
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    format!(
                        "cannot inspect newly created {kind} directory {}: {error}",
                        current.display()
                    )
                })?;
                validate_directory(&current, &metadata, current == path, kind)?;
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect {kind} directory {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path, kind: &str) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "cannot create private {kind} directory {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path, kind: &str) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "cannot create {kind} directory {}: {error}",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn validate_directory(
    path: &Path,
    metadata: &fs::Metadata,
    final_parent: bool,
    kind: &str,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symbolic link in {kind} path: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{kind} path component is not a directory: {}",
            path.display()
        ));
    }

    let effective_uid = nix::unistd::geteuid().as_raw();
    let owner = metadata.uid();
    let mode = metadata.mode() & 0o7777;
    if final_parent {
        if owner != effective_uid {
            return Err(format!(
                "{kind} directory {} must be owned by effective UID {}",
                path.display(),
                effective_uid
            ));
        }
        if mode != 0o700 {
            return Err(format!(
                "{kind} directory {} must have mode 0700, got {mode:04o}",
                path.display()
            ));
        }
        return Ok(());
    }

    if owner != 0 && owner != effective_uid {
        return Err(format!(
            "{kind} path ancestor {} is owned by unexpected UID {owner}",
            path.display()
        ));
    }
    let root_owned_sticky_directory = owner == 0 && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !root_owned_sticky_directory {
        return Err(format!(
            "{kind} path ancestor {} is writable by group or other users",
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
    kind: &str,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symbolic link in {kind} path: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{kind} path component is not a directory: {}",
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
    let lock_kind = format!("{} lock", security.description());
    if security.is_private() {
        reject_symlink(&lock_path, &lock_kind)?;
    }

    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    if security.is_private() {
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options
        .open(&lock_path)
        .map_err(|error| format!("cannot open registry lock {}: {error}", lock_path.display()))?;
    if security.is_private() {
        validate_private_file(&file, &lock_path, &lock_kind)?;
    }
    Ok(file)
}

fn load(path: &Path, security: RegistrySecurity) -> Result<DocumentMut, String> {
    load_with_policy(path, security, false).map(|(document, _)| document)
}

fn load_required(path: &Path, security: RegistrySecurity) -> Result<DocumentMut, String> {
    load_with_policy(path, security, true).map(|(document, _)| document)
}

fn load_with_policy(
    path: &Path,
    security: RegistrySecurity,
    require_existing: bool,
) -> Result<(DocumentMut, bool), String> {
    #[cfg(test)]
    if security == RegistrySecurity::DerivedState {
        DERIVED_IO_COUNTS.with(|counts| {
            let mut count = counts.get();
            count.reads += 1;
            counts.set(count);
        });
    }
    let mut document = match read_content(path, security)? {
        Some(content) => content
            .parse::<DocumentMut>()
            .map_err(|error| format!("cannot parse {}: {error}", path.display()))?,
        None if require_existing => {
            return Err(format!(
                "{} {} does not exist",
                security.description(),
                path.display()
            ));
        }
        None if security == RegistrySecurity::DerivedState => DocumentMut::new(),
        None => "[ports]\n"
            .parse::<DocumentMut>()
            .expect("the empty registry document is valid TOML"),
    };
    if security == RegistrySecurity::DerivedState {
        return Ok((document, false));
    }
    if security == RegistrySecurity::LogicalWorkload
        && document.get("ports").is_some()
        && !document.contains_table("ports")
    {
        return Err("logical Workload registry [ports] value must be a table".to_string());
    }
    ensure_ports_table(&mut document);
    let migrated = migrate_legacy_assignments(&mut document);
    if security == RegistrySecurity::LogicalWorkload {
        validate_logical_assignments(&document)?;
    }
    Ok((document, migrated))
}

fn read_content(path: &Path, security: RegistrySecurity) -> Result<Option<String>, String> {
    if !security.is_private() {
        return match fs::read_to_string(path) {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        };
    }

    let kind = security.description();
    reject_symlink(path, kind)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!("cannot open {kind} {}: {error}", path.display()));
        }
    };
    validate_private_file(&file, path, kind)?;
    let length = file
        .metadata()
        .map_err(|error| format!("cannot inspect {kind} {}: {error}", path.display()))?
        .len();
    if length > MAX_PRIVATE_FILE_BYTES {
        return Err(format!(
            "{kind} {} exceeds the {} byte limit",
            path.display(),
            MAX_PRIVATE_FILE_BYTES
        ));
    }
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

fn reject_existing(path: &Path, kind: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "refusing to overwrite existing {kind}: {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect {kind} {}: {error}", path.display())),
    }
}

fn validate_existing_private_file(path: &Path, kind: &str) -> Result<(), String> {
    reject_symlink(path, kind)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    match options.open(path) {
        Ok(file) => validate_private_file(&file, path, kind),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot open {kind} {}: {error}", path.display())),
    }
}

fn require_existing_private_file(path: &Path, kind: &str) -> Result<(), String> {
    reject_symlink(path, kind)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    match options.open(path) {
        Ok(file) => validate_private_file(&file, path, kind),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(format!("{kind} {} does not exist", path.display()))
        }
        Err(error) => Err(format!("cannot open {kind} {}: {error}", path.display())),
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

fn migrate_legacy_assignments(document: &mut DocumentMut) -> bool {
    let old_entries = document["ports"]
        .as_table()
        .map(|ports| {
            ports
                .iter()
                .filter_map(|(key, value)| value.as_integer().map(|port| (key.to_string(), port)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let migrated = !old_entries.is_empty();
    for (workload, port) in old_entries {
        document["ports"][&workload] = toml_edit::table();
        document["ports"][&workload][DEFAULT_ROLE] = value(port);
    }
    migrated
}

fn validate_logical_assignments(document: &DocumentMut) -> Result<(), String> {
    logical_assignments(document).map(|_| ())
}

pub(crate) fn logical_assignments(document: &DocumentMut) -> Result<LogicalAssignments, String> {
    let ports = document
        .get("ports")
        .and_then(|ports| ports.as_table())
        .ok_or_else(|| "logical Workload registry must contain a [ports] table".to_string())?;
    let mut ports_by_assignment = BTreeMap::new();
    let mut assignments_by_port = BTreeMap::new();
    for (workload, roles) in ports {
        validate_workload_id(workload)
            .map_err(|error| format!("invalid registry Workload {workload:?}: {error}"))?;
        let roles = roles.as_table().ok_or_else(|| {
            format!("registry Workload {workload:?} must contain a role-to-port table")
        })?;
        for (role, port) in roles {
            validate_role(role)
                .map_err(|error| format!("invalid registry role {workload:?}/{role:?}: {error}"))?;
            let port = port.as_integer().ok_or_else(|| {
                format!("registry assignment {workload:?}/{role:?} must be an integer")
            })?;
            if !(1..=LAST_ASSIGNED_PORT).contains(&port) {
                return Err(format!(
                    "registry assignment {workload:?}/{role:?} must be a TCP port from 1 through {LAST_ASSIGNED_PORT}, got {port}"
                ));
            }
            if let Some(previous) = assignments_by_port.insert(port, format!("{workload}/{role}")) {
                return Err(format!(
                    "registry port {port} is assigned to both {previous} and {workload}/{role}"
                ));
            }
            ports_by_assignment.insert(
                (workload.to_string(), role.to_string()),
                u16::try_from(port).expect("validated logical registry ports fit u16"),
            );
        }
    }
    Ok(ports_by_assignment)
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
    if security.is_private() && content.len() as u64 > MAX_PRIVATE_FILE_BYTES {
        return Err(format!(
            "{} {} exceeds the {} byte limit",
            security.description(),
            path.display(),
            MAX_PRIVATE_FILE_BYTES
        ));
    }
    AtomicFile::new(path, AllowOverwrite)
        .write(|file| {
            #[cfg(unix)]
            if security.is_private() {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(content.as_bytes())
        })
        .map_err(|error| format!("cannot atomically write {}: {error}", path.display()))?;

    if security.is_private() {
        let kind = security.description();
        reject_symlink(path, kind)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        let file = options.open(path).map_err(|error| {
            format!(
                "cannot validate {kind} {} after write: {error}",
                path.display()
            )
        })?;
        validate_private_file(&file, path, kind)?;
    }
    #[cfg(test)]
    if security == RegistrySecurity::DerivedState {
        DERIVED_IO_COUNTS.with(|counts| {
            let mut count = counts.get();
            count.writes += 1;
            count.route_entries_written += document
                .get("discovered_routes")
                .and_then(|routes| routes.as_table())
                .map_or(0, toml_edit::Table::len);
            counts.set(count);
        });
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

#[cfg(test)]
mod tests {
    use super::{
        MAX_PRIVATE_FILE_BYTES, RegistrySecurity, allocate, read, replace, resolve_private_path,
        update_until, write_new,
    };
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::{TempDir, tempdir_in};
    use toml_edit::{DocumentMut, value};

    fn tempdir() -> std::io::Result<TempDir> {
        #[cfg(unix)]
        let root = Path::new("/tmp").canonicalize()?;
        #[cfg(not(unix))]
        let root = std::env::temp_dir().canonicalize()?;
        let directory = tempdir_in(root)?;
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn padded_document(source: &str, length: usize) -> DocumentMut {
        let content = format!("{source}#{}\n", "x".repeat(length - source.len() - 2));
        let document = content.parse::<DocumentMut>().unwrap();
        assert!(document.to_string() == content, "fixture must round-trip");
        document
    }

    fn assert_published(path: &Path, security: RegistrySecurity, expected: &str) {
        assert!(
            fs::read_to_string(path).unwrap() == expected,
            "published bytes must match, including comments"
        );
        assert!(
            read(path, security).unwrap().to_string() == expected,
            "published state must remain readable"
        );
    }

    #[test]
    fn private_allocation_respects_serialized_byte_limit() {
        let source = "[ports.existing]\nmain = 4001\n";
        let mut allocated = source.parse::<DocumentMut>().unwrap();
        allocated["ports"]["added-web"] = toml_edit::table();
        allocated["ports"]["added-web"]["main"] = value(4002);
        let growth = allocated.to_string().len() - source.len();
        let security = RegistrySecurity::LogicalWorkload;

        for excess in [0, 1] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("ports.toml");
            let target_length = MAX_PRIVATE_FILE_BYTES as usize + excess;
            let original = padded_document(source, target_length - growth);
            let mut expected = original.clone();
            expected["ports"]["added-web"] = allocated["ports"]["added-web"].clone();
            assert_eq!(expected.to_string().len(), target_length);
            write_new(&path, security, &original).unwrap();
            assert_published(&path, security, &original.to_string());

            let result = allocate(&path, "added-web", "main", true);
            if excess == 0 {
                assert_eq!(result.unwrap(), (4002, true));
                assert_published(&path, security, &expected.to_string());
                assert_eq!(
                    allocate(&path, "added-web", "main", true).unwrap(),
                    (4002, false)
                );
            } else {
                assert!(
                    result.is_err(),
                    "allocation accepted {} serialized bytes above the private limit",
                    fs::metadata(&path).unwrap().len()
                );
                assert!(
                    result
                        .unwrap_err()
                        .contains(&format!("exceeds the {MAX_PRIVATE_FILE_BYTES} byte limit"))
                );
                assert_published(&path, security, &original.to_string());
            }
        }
    }

    #[test]
    fn private_publication_paths_respect_serialized_byte_limit() {
        let source = "[ports.existing]\nmain = 4001\n";
        let exact = padded_document(source, MAX_PRIVATE_FILE_BYTES as usize);
        let oversized = padded_document(source, MAX_PRIVATE_FILE_BYTES as usize + 1);
        let expected_error = format!("exceeds the {MAX_PRIVATE_FILE_BYTES} byte limit");

        for security in [
            RegistrySecurity::LogicalWorkload,
            RegistrySecurity::DerivedState,
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("state.toml");
            assert!(
                write_new(&path, security, &oversized)
                    .unwrap_err()
                    .contains(&expected_error)
            );
            assert!(!path.exists(), "oversized creation must not publish state");

            write_new(&path, security, &exact).unwrap();
            assert_published(&path, security, &exact.to_string());
            assert!(
                replace(&path, security, &oversized)
                    .unwrap_err()
                    .contains(&expected_error)
            );
            assert_published(&path, security, &exact.to_string());
            replace(&path, security, &exact).unwrap();
            assert_published(&path, security, &exact.to_string());

            update_until(&path, security, None, |_| Ok(())).unwrap();
            let error = update_until(&path, security, None, |document| {
                document["ports"]["existing"]["main"] = value(40010);
                Ok(())
            })
            .unwrap_err();
            assert!(error.contains(&expected_error));
            assert_published(&path, security, &exact.to_string());
        }
    }

    #[test]
    fn private_byte_limit_accounts_for_legacy_serialization_without_limiting_development() {
        let original = padded_document(
            "[ports]\nexisting = 4001\n",
            MAX_PRIVATE_FILE_BYTES as usize,
        )
        .to_string();

        for security in [
            RegistrySecurity::LogicalWorkload,
            RegistrySecurity::Development,
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("ports.toml");
            fs::write(&path, &original).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let migrated = read(&path, security).unwrap();
            assert!(migrated.to_string().len() > MAX_PRIVATE_FILE_BYTES as usize);
            assert_eq!(
                migrated["ports"]["existing"]["main"].as_integer(),
                Some(4001)
            );

            let result = allocate(&path, "existing", "main", security.is_private());
            if security.is_private() {
                assert!(
                    result
                        .unwrap_err()
                        .contains(&format!("exceeds the {MAX_PRIVATE_FILE_BYTES} byte limit"))
                );
                assert!(fs::read_to_string(&path).unwrap() == original);
                assert!(
                    read(&path, security).unwrap().to_string() == migrated.to_string(),
                    "rejected migration must preserve readable assignments"
                );
            } else {
                assert_eq!(result.unwrap(), (4001, false));
                assert_published(&path, security, &migrated.to_string());
            }
        }
    }

    #[test]
    fn private_paths_are_lexically_normalized_before_validation() {
        let raw = Path::new("/var/lib/phx-port/./ports.toml");
        let normalized = resolve_private_path(raw, "logical Workload registry").unwrap();
        assert_eq!(
            normalized.as_os_str(),
            Path::new("/var/lib/phx-port/ports.toml").as_os_str()
        );
    }
}
