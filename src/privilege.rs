#[cfg(unix)]
use std::ffi::CString;

#[cfg(unix)]
const MAX_SUPPLEMENTARY_GROUPS: usize = 1_024;

#[cfg(unix)]
pub struct PreparedPrivilegeDrop {
    name: String,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
    groups: Vec<nix::unistd::Gid>,
}

#[cfg(not(unix))]
pub struct PreparedPrivilegeDrop;

pub fn prepare(run_as: Option<&str>) -> Result<Option<PreparedPrivilegeDrop>, String> {
    #[cfg(unix)]
    {
        let effective_uid = nix::unistd::geteuid();
        match (effective_uid.is_root(), run_as) {
            (false, None) => Ok(None),
            (false, Some(_)) => {
                Err("--run-as requires the daemon to start with effective UID 0".to_string())
            }
            (true, None) => Err(
                "refusing to run the daemon as UID 0; use --run-as USER with explicit --listen addresses"
                    .to_string(),
            ),
            (true, Some(name)) => PreparedPrivilegeDrop::resolve(name).map(Some),
        }
    }

    #[cfg(not(unix))]
    match run_as {
        Some(_) => Err("--run-as is supported only on Unix platforms".to_string()),
        None => Ok(None),
    }
}

#[cfg(unix)]
impl PreparedPrivilegeDrop {
    fn resolve(name: &str) -> Result<Self, String> {
        if name.len() > 256 || name.chars().any(char::is_control) {
            return Err("--run-as user name is invalid".to_string());
        }
        let user = nix::unistd::User::from_name(name)
            .map_err(|error| format!("cannot resolve --run-as user {name:?}: {error}"))?
            .ok_or_else(|| format!("--run-as user {name:?} does not exist"))?;
        if user.uid.is_root() {
            return Err("--run-as must select a non-root user".to_string());
        }
        if user.gid.as_raw() == 0 {
            return Err("--run-as must select a user with a non-root primary group".to_string());
        }
        let name_c = CString::new(user.name.as_bytes())
            .map_err(|_| "--run-as user name contains a NUL byte".to_string())?;
        let groups = resolve_groups(&name_c, user.gid.as_raw())?;
        if groups.iter().any(|group| group.as_raw() == 0) {
            return Err("--run-as user must not belong to the root group".to_string());
        }

        Ok(Self {
            name: user.name,
            uid: user.uid,
            gid: user.gid,
            groups,
        })
    }

    pub fn apply(self) -> Result<(), String> {
        set_supplementary_groups(&self.groups).map_err(|error| {
            format!(
                "cannot initialize supplementary groups for --run-as user {:?}: {error}",
                self.name
            )
        })?;
        if unsafe { nix::libc::setgid(self.gid.as_raw()) } == -1 {
            return Err(format!(
                "cannot set GID {} for --run-as user {:?}: {}",
                self.gid,
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { nix::libc::setuid(self.uid.as_raw()) } == -1 {
            return Err(format!(
                "cannot set UID {} for --run-as user {:?}: {}",
                self.uid,
                self.name,
                std::io::Error::last_os_error()
            ));
        }

        verify_identity(self.uid, self.gid, &self.groups)?;
        verify_root_cannot_be_regained(self.uid, self.gid)?;
        enable_no_new_privileges()?;
        verify_identity(self.uid, self.gid, &self.groups)?;

        eprintln!(
            "Dropped privileges to {} (uid {}, gid {})",
            self.name, self.uid, self.gid
        );
        Ok(())
    }
}

#[cfg(unix)]
fn resolve_groups(
    name: &CString,
    primary_gid: nix::libc::gid_t,
) -> Result<Vec<nix::unistd::Gid>, String> {
    let primary_gid = nix::unistd::Gid::from_raw(primary_gid);
    let mut groups = supplementary_groups_for_user(name, primary_gid).map_err(|error| {
        format!(
            "cannot resolve supplementary groups for --run-as user {:?}: {error}",
            name
        )
    })?;
    if groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        return Err(format!(
            "supplementary group set for --run-as user {:?} exceeds the safety limit of {MAX_SUPPLEMENTARY_GROUPS}",
            name
        ));
    }
    groups.sort_unstable_by_key(|group| group.as_raw());
    groups.dedup();
    if !groups.contains(&primary_gid) {
        groups.push(primary_gid);
        groups.sort_unstable_by_key(|group| group.as_raw());
    }
    Ok(groups)
}

#[cfg(unix)]
fn verify_identity(
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
    expected_groups: &[nix::unistd::Gid],
) -> Result<(), String> {
    let real_uid = unsafe { nix::libc::getuid() };
    let effective_uid = unsafe { nix::libc::geteuid() };
    let real_gid = unsafe { nix::libc::getgid() };
    let effective_gid = unsafe { nix::libc::getegid() };
    if real_uid != uid.as_raw()
        || effective_uid != uid.as_raw()
        || real_gid != gid.as_raw()
        || effective_gid != gid.as_raw()
    {
        return Err(format!(
            "privilege drop verification failed: uid={real_uid}, euid={effective_uid}, gid={real_gid}, egid={effective_gid}; expected uid={uid}, gid={gid}"
        ));
    }

    let mut groups = current_supplementary_groups().map_err(|error| {
        format!("cannot inspect supplementary groups after privilege drop: {error}")
    })?;
    groups.sort_unstable_by_key(|group| group.as_raw());
    groups.dedup();
    if groups != expected_groups {
        return Err(format!(
            "supplementary group verification failed after privilege drop: got {groups:?}, expected {expected_groups:?}"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn supplementary_groups_for_user(
    name: &CString,
    primary_gid: nix::unistd::Gid,
) -> Result<Vec<nix::unistd::Gid>, String> {
    nix::unistd::getgrouplist(name, primary_gid).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn supplementary_groups_for_user(
    name: &CString,
    primary_gid: nix::unistd::Gid,
) -> Result<Vec<nix::unistd::Gid>, String> {
    let primary_gid = nix::libc::c_int::try_from(primary_gid.as_raw())
        .map_err(|_| "primary GID does not fit the Darwin group API".to_string())?;
    let mut groups = vec![primary_gid];
    loop {
        let mut count = nix::libc::c_int::try_from(groups.len())
            .map_err(|_| "supplementary group count overflowed".to_string())?;
        let result = unsafe {
            nix::libc::getgrouplist(name.as_ptr(), primary_gid, groups.as_mut_ptr(), &mut count)
        };
        if result >= 0 {
            let count = usize::try_from(count)
                .map_err(|_| "supplementary group count was negative".to_string())?;
            groups.truncate(count);
            return groups
                .into_iter()
                .map(|group| {
                    u32::try_from(group)
                        .map(nix::unistd::Gid::from_raw)
                        .map_err(|_| "Darwin returned a negative supplementary GID".to_string())
                })
                .collect();
        }

        let required = usize::try_from(count)
            .map_err(|_| "supplementary group count was negative".to_string())?;
        if required <= groups.len() || required > MAX_SUPPLEMENTARY_GROUPS {
            return Err(format!(
                "supplementary group count exceeds the safety limit of {MAX_SUPPLEMENTARY_GROUPS}"
            ));
        }
        groups.resize(required, primary_gid);
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn supplementary_groups_for_user(
    _name: &CString,
    _primary_gid: nix::unistd::Gid,
) -> Result<Vec<nix::unistd::Gid>, String> {
    Err("--run-as is supported only on Linux and macOS".to_string())
}

#[cfg(target_os = "linux")]
fn set_supplementary_groups(groups: &[nix::unistd::Gid]) -> Result<(), String> {
    nix::unistd::setgroups(groups).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn set_supplementary_groups(groups: &[nix::unistd::Gid]) -> Result<(), String> {
    let count = nix::libc::c_int::try_from(groups.len())
        .map_err(|_| "supplementary group count overflowed".to_string())?;
    let raw = groups
        .iter()
        .map(|group| group.as_raw())
        .collect::<Vec<_>>();
    if unsafe { nix::libc::setgroups(count, raw.as_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn set_supplementary_groups(_groups: &[nix::unistd::Gid]) -> Result<(), String> {
    Err("--run-as is supported only on Linux and macOS".to_string())
}

#[cfg(target_os = "linux")]
fn current_supplementary_groups() -> Result<Vec<nix::unistd::Gid>, String> {
    nix::unistd::getgroups().map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn current_supplementary_groups() -> Result<Vec<nix::unistd::Gid>, String> {
    let count = unsafe { nix::libc::getgroups(0, std::ptr::null_mut()) };
    if count == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut groups = vec![
        0;
        usize::try_from(count)
            .map_err(|_| "supplementary group count was negative".to_string())?
    ];
    if count > 0 && unsafe { nix::libc::getgroups(count, groups.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(groups.into_iter().map(nix::unistd::Gid::from_raw).collect())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn current_supplementary_groups() -> Result<Vec<nix::unistd::Gid>, String> {
    Err("--run-as is supported only on Linux and macOS".to_string())
}

#[cfg(unix)]
fn verify_root_cannot_be_regained(
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
) -> Result<(), String> {
    if unsafe { nix::libc::seteuid(0) } == 0 {
        let _ = unsafe { nix::libc::setuid(uid.as_raw()) };
        return Err("privilege drop was reversible: effective UID 0 could be regained".to_string());
    }
    let uid_error = std::io::Error::last_os_error();
    if uid_error.raw_os_error() != Some(nix::libc::EPERM) {
        return Err(format!(
            "privilege drop could not prove UID 0 is unavailable: {uid_error}"
        ));
    }

    if unsafe { nix::libc::setegid(0) } == 0 {
        let _ = unsafe { nix::libc::setgid(gid.as_raw()) };
        return Err("privilege drop was reversible: effective GID 0 could be regained".to_string());
    }
    let gid_error = std::io::Error::last_os_error();
    if gid_error.raw_os_error() != Some(nix::libc::EPERM) {
        return Err(format!(
            "privilege drop could not prove GID 0 is unavailable: {gid_error}"
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
impl PreparedPrivilegeDrop {
    pub fn apply(self) -> Result<(), String> {
        Err("--run-as is supported only on Unix platforms".to_string())
    }
}

#[cfg(target_os = "linux")]
fn enable_no_new_privileges() -> Result<(), String> {
    if unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(format!(
            "cannot enable Linux no_new_privs after privilege drop: {}",
            std::io::Error::last_os_error()
        ));
    }
    let value = unsafe { nix::libc::prctl(nix::libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if value != 1 {
        return Err(format!(
            "Linux no_new_privs verification returned unexpected value {value}"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enable_no_new_privileges() -> Result<(), String> {
    Ok(())
}
