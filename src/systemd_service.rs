use atomicwrites::{AllowOverwrite, AtomicFile};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const SERVICE_NAME: &str = "phx-port.service";

pub fn install(config: &Path) -> Result<PathBuf, String> {
    ensure_linux()?;
    let path = unit_path()?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot locate phx-port executable: {error}"))?;
    let config = absolute_path(config)?;
    let unit = render_unit(&executable, &config)?;

    let directory = path
        .parent()
        .ok_or_else(|| "systemd unit path has no parent directory".to_string())?;
    fs::create_dir_all(directory).map_err(|error| {
        format!(
            "cannot create systemd user directory {}: {error}",
            directory.display()
        )
    })?;
    AtomicFile::new(&path, AllowOverwrite)
        .write(|file| file.write_all(unit.as_bytes()))
        .map_err(|error| format!("cannot write systemd unit {}: {error}", path.display()))?;

    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", SERVICE_NAME])?;
    Ok(path)
}

pub fn uninstall() -> Result<PathBuf, String> {
    ensure_linux()?;
    let path = unit_path()?;
    if !path.exists() {
        return Err(format!(
            "systemd user service is not installed at {}",
            path.display()
        ));
    }

    systemctl(&["disable", "--now", SERVICE_NAME])?;
    fs::remove_file(&path)
        .map_err(|error| format!("cannot remove systemd unit {}: {error}", path.display()))?;
    systemctl(&["daemon-reload"])?;
    Ok(path)
}

fn ensure_linux() -> Result<(), String> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err("systemd user-service management is supported only on Linux".to_string())
    }
}

fn unit_path() -> Result<PathBuf, String> {
    let config_home = if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else {
        let home = env::var_os("HOME")
            .ok_or_else(|| "HOME is not set and XDG_CONFIG_HOME is unavailable".to_string())?;
        PathBuf::from(home).join(".config")
    };
    Ok(config_home.join("systemd/user").join(SERVICE_NAME))
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|error| format!("cannot resolve configuration path: {error}"))
}

fn render_unit(executable: &Path, config: &Path) -> Result<String, String> {
    let executable = quote_unit_value(executable, "executable")?;
    let config = quote_unit_value(config, "configuration")?;
    Ok(format!(
        "[Unit]\n\
         Description=phx-port dynamic TLS/SNI proxy\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         Environment=\"PHX_PORT_CONFIG={config}\"\n\
         ExecStart=\"{executable}\" daemon\n\
         Restart=on-failure\n\
         RestartSec=2s\n\
         TimeoutStopSec=35s\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    ))
}

fn quote_unit_value(path: &Path, description: &str) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("{description} path is not valid UTF-8: {}", path.display()))?;
    if value.chars().any(char::is_control) {
        return Err(format!("{description} path contains a control character"));
    }
    Ok(value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%"))
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(|error| format!("cannot run systemctl --user: {error}"))?;
    if output.status.success() {
        return Ok(());
    }

    let detail = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "systemctl --user {} failed with {}: {}",
        args.join(" "),
        output.status,
        detail.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::{quote_unit_value, render_unit};
    use std::path::Path;

    #[test]
    fn unit_uses_absolute_binary_and_configuration_paths() {
        let unit = render_unit(
            Path::new("/home/user/bin/phx-port"),
            Path::new("/home/user/.config/phx-ports.toml"),
        )
        .unwrap();

        assert!(unit.contains("ExecStart=\"/home/user/bin/phx-port\" daemon"));
        assert!(unit.contains("Environment=\"PHX_PORT_CONFIG=/home/user/.config/phx-ports.toml\""));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("TimeoutStopSec=35s"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn unit_paths_escape_quotes_backslashes_and_specifiers() {
        assert_eq!(
            quote_unit_value(Path::new("/tmp/a b/100%/a\"b\\c"), "test").unwrap(),
            "/tmp/a b/100%%/a\\\"b\\\\c"
        );
    }
}
