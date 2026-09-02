use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{IsTerminal, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};
use toml_edit::DocumentMut;

mod admission;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod discover_tests;
mod handoff;
mod handoff_protocol;
#[cfg(any(target_os = "macos", test))]
mod handoff_stream;
mod ingress_config;
mod ingress_limits;
mod port_registry;
mod proxy;
mod route_cache;
mod systemd_service;
mod tls_client_hello;
mod worker_pool;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_ROLE: &str = "main";

const HELP: &str = "\
phx-port — stable port assignments for your projects

USAGE:
    PORT=$(phx-port) iex -S mix phx.server
    PORT=$(phx-port) PORT_DEBUG=$(phx-port debug) my-app

    phx-port list               Show ports as a directory tree with clickable URLs
    phx-port list --flat        List all registered projects and ports (flat)
    phx-port list --port-only   Show tree with port numbers instead of URLs
    phx-port register           Register the current directory for a new port
    phx-port register debug     Register a named port role
    phx-port --workload-id ID [ROLE]
                                Allocate by logical Workload ID instead of directory
    phx-port delete <X>         Remove all ports (X = port number, directory name, or '.')
    phx-port delete <X> debug   Remove a specific port role
    phx-port running            Show which registered projects are currently running
    phx-port discover           Open a browser page to pick a running project
    phx-port daemon [--listen ADDRESS]... [--ingress-config PATH] [CAPACITY OPTIONS]
                                Route TLS by SNI to live https/main workloads
    phx-port proxy status       Show live daemon state and counters
    phx-port proxy routes       Show persistently discovered TLS routes
    phx-port proxy stop         Gracefully stop the running daemon
    phx-port proxy install-service
                                Install and start the systemd user service
    phx-port proxy uninstall-service
                                Stop and remove the systemd user service
    phx-port open               Open default browser for the current directory's port
    phx-port open debug         Open browser for a named port role
    phx-port launch             Alias for 'open'

When piped (e.g. in a script), prints the port for the current directory,
auto-registering if needed. An optional positional argument specifies the
port role (default: main). Port 4000 is kept free.

Config: ~\\.config\\phx-ports.toml (override with PHX_PORT_CONFIG env var)
Logical Workload: PHX_PORT_WORKLOAD_ID or --workload-id ID
Public profile: PHX_PORT_INGRESS_CONFIG or daemon --ingress-config PATH
Home:   USERPROFILE or HOMEDRIVE+HOMEPATH (Windows), HOME (Linux/macOS)";

fn home_dir() -> PathBuf {
    #[cfg(target_family = "windows")]
    {
        if let Ok(profile) = env::var("USERPROFILE") {
            return PathBuf::from(profile);
        }
        if let (Ok(drive), Ok(path)) = (env::var("HOMEDRIVE"), env::var("HOMEPATH")) {
            return PathBuf::from(format!("{}{}", drive, path));
        }
        eprintln!(
            "Error: could not determine home directory (USERPROFILE or HOMEDRIVE+HOMEPATH not set)"
        );
        process::exit(1);
    }
    #[cfg(not(target_family = "windows"))]
    {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home);
        }
        eprintln!("Error: HOME environment variable not set");
        process::exit(1);
    }
}

pub(crate) fn config_path() -> PathBuf {
    if let Ok(custom) = env::var("PHX_PORT_CONFIG") {
        return PathBuf::from(custom);
    }
    home_dir().join(".config").join("phx-ports.toml")
}

pub(crate) fn read_config(path: &Path) -> DocumentMut {
    port_registry::read(path, port_registry::RegistrySecurity::Development)
        .unwrap_or_else(exit_registry_error)
}

pub(crate) fn update_config<R>(path: &Path, update: impl FnOnce(&mut DocumentMut) -> R) -> R {
    port_registry::update(
        path,
        port_registry::RegistrySecurity::Development,
        |document| Ok(update(document)),
    )
    .unwrap_or_else(exit_registry_error)
}

fn cwd_string() -> String {
    env::current_dir()
        .unwrap_or_else(|e| {
            eprintln!("Error getting current directory: {}", e);
            process::exit(1);
        })
        .to_string_lossy()
        .to_string()
}

fn ensure_ports_table(document: &mut DocumentMut) {
    if !document.contains_table("ports") {
        document["ports"] = toml_edit::table();
    }
}

fn exit_registry_error<T>(error: String) -> T {
    eprintln!("Error: {error}");
    process::exit(1);
}

#[derive(Debug, Eq, PartialEq)]
struct AllocationIdentity {
    key: String,
    logical: bool,
}

fn allocation_identity(explicit_workload_id: Option<&str>) -> Result<AllocationIdentity, String> {
    let workload_id = match explicit_workload_id {
        Some(workload_id) => Some(workload_id.to_string()),
        None => match env::var("PHX_PORT_WORKLOAD_ID") {
            Ok(workload_id) => Some(workload_id),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                return Err("PHX_PORT_WORKLOAD_ID must be valid UTF-8".to_string());
            }
        },
    };
    if let Some(workload_id) = workload_id {
        port_registry::validate_workload_id(&workload_id)?;
        return Ok(AllocationIdentity {
            key: workload_id,
            logical: true,
        });
    }
    Ok(AllocationIdentity {
        key: cwd_string(),
        logical: false,
    })
}

fn parse_allocation_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let mut role = None;
    let mut workload_id = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--workload-id" => {
                if workload_id.is_some() {
                    return Err("--workload-id may be specified only once".to_string());
                }
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--workload-id requires a value".to_string())?;
                workload_id = Some(value.clone());
                index += 2;
            }
            option if option.starts_with('-') => {
                return Err(format!("unknown allocation option: {option}"));
            }
            value => {
                if role.replace(value.to_string()).is_some() {
                    return Err("port allocation accepts at most one role".to_string());
                }
                index += 1;
            }
        }
    }
    Ok((
        role.unwrap_or_else(|| DEFAULT_ROLE.to_string()),
        workload_id,
    ))
}

fn cmd_list(config: &Path) {
    let doc = read_config(config);
    if let Some(table) = doc.get("ports").and_then(|v| v.as_table()) {
        let mut entries: Vec<(i64, String, String)> = Vec::new();
        for (dir, dir_value) in table.iter() {
            if let Some(dir_table) = dir_value.as_table() {
                for (role, port_value) in dir_table.iter() {
                    if let Some(port) = port_value.as_integer() {
                        entries.push((port, dir.to_string(), role.to_string()));
                    }
                }
            }
        }
        if entries.is_empty() {
            eprintln!("No ports registered. Use 'register' or PORT=$(phx-port) to add one.");
            return;
        }
        entries.sort_by_key(|(p, _, _)| *p);
        for (port, dir, role) in &entries {
            if role == DEFAULT_ROLE {
                println!("{:>5}  {}", port, dir);
            } else {
                println!("{:>5}  {} ({})", port, dir, role);
            }
        }
    } else {
        eprintln!("No ports registered.");
    }
}

struct TreeNode {
    children: BTreeMap<String, TreeNode>,
    ports: Vec<(i64, String)>,
}

impl TreeNode {
    fn new() -> Self {
        TreeNode {
            children: BTreeMap::new(),
            ports: Vec::new(),
        }
    }

    fn insert(&mut self, segments: &[&str], ports: Vec<(i64, String)>) {
        if segments.is_empty() {
            self.ports = ports;
            return;
        }
        self.children
            .entry(segments[0].to_string())
            .or_insert_with(TreeNode::new)
            .insert(&segments[1..], ports);
    }

    fn collapse(&mut self) {
        for child in self.children.values_mut() {
            child.collapse();
        }
        let keys: Vec<String> = self.children.keys().cloned().collect();
        for key in keys {
            let should_merge = self
                .children
                .get(&key)
                .is_some_and(|c| c.children.len() == 1 && c.ports.is_empty());
            if should_merge {
                let child = self.children.remove(&key).unwrap();
                let (gk, gv) = child.children.into_iter().next().unwrap();
                self.children.insert(format!("{}/{}", key, gk), gv);
            }
        }
    }
}

fn format_ports(ports: &[(i64, String)], as_url: bool) -> String {
    let mut sorted = ports.to_vec();
    sorted.sort_by_key(|(p, _)| *p);
    sorted
        .iter()
        .map(|(p, r)| {
            let port_str = if as_url {
                format!("http://localhost:{}", p)
            } else {
                format!("{}", p)
            };
            if r == DEFAULT_ROLE {
                port_str
            } else {
                format!("{} ({})", port_str, r)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

struct TreeLine {
    prefix: String,
    name: String,
    port_info: Option<String>,
    name_end: usize,
}

fn collect_tree_lines(
    node: &TreeNode,
    prefix: &str,
    depth: usize,
    as_url: bool,
    lines: &mut Vec<TreeLine>,
) {
    let children: Vec<(&String, &TreeNode)> = node.children.iter().collect();
    for (i, (name, child)) in children.iter().enumerate() {
        let is_last = i == children.len() - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let continuation = if is_last { "    " } else { "│   " };
        let name_end = depth * 4 + 4 + name.chars().count();

        lines.push(TreeLine {
            prefix: format!("{}{}", prefix, connector),
            name: name.to_string(),
            port_info: if child.ports.is_empty() {
                None
            } else {
                Some(format_ports(&child.ports, as_url))
            },
            name_end,
        });

        collect_tree_lines(
            child,
            &format!("{}{}", prefix, continuation),
            depth + 1,
            as_url,
            lines,
        );
    }
}

fn cmd_list_tree(config: &Path, as_url: bool) {
    let doc = read_config(config);
    let table = match doc.get("ports").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => {
            eprintln!("No ports registered.");
            return;
        }
    };

    let mut dir_ports: BTreeMap<String, Vec<(i64, String)>> = BTreeMap::new();
    for (dir, dir_value) in table.iter() {
        if let Some(dir_table) = dir_value.as_table() {
            let ports: Vec<(i64, String)> = dir_table
                .iter()
                .filter_map(|(role, v)| v.as_integer().map(|p| (p, role.to_string())))
                .collect();
            if !ports.is_empty() {
                dir_ports.insert(dir.to_string(), ports);
            }
        }
    }

    if dir_ports.is_empty() {
        eprintln!("No ports registered. Use 'register' or PORT=$(phx-port) to add one.");
        return;
    }

    let home = home_dir().to_string_lossy().to_string();
    let mut root = TreeNode::new();

    for (dir, ports) in &dir_ports {
        let relative = dir.strip_prefix(&home).unwrap_or(dir.as_str());
        let relative = relative.strip_prefix('/').unwrap_or(relative);
        let segments: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
        root.insert(&segments, ports.clone());
    }

    root.collapse();

    // Collapse single-child root chain into the display path
    let mut display_root = home;
    let mut render_node = &root;
    while render_node.children.len() == 1 && render_node.ports.is_empty() {
        let (name, child) = render_node.children.iter().next().unwrap();
        display_root = format!("{}/{}", display_root, name);
        render_node = child;
    }

    if render_node.children.is_empty() {
        if !render_node.ports.is_empty() {
            println!(
                "{} .. {}",
                display_root,
                format_ports(&render_node.ports, as_url)
            );
        }
        return;
    }

    let mut lines = Vec::new();
    collect_tree_lines(render_node, "", 0, as_url, &mut lines);

    let max_end = lines
        .iter()
        .filter(|l| l.port_info.is_some())
        .map(|l| l.name_end)
        .max()
        .unwrap_or(0);
    let target = max_end + 2;

    println!("{}", display_root);
    for line in &lines {
        match &line.port_info {
            Some(ports) => {
                let dots = target.saturating_sub(line.name_end).max(2);
                println!(
                    "{}{} {} {}",
                    line.prefix,
                    line.name,
                    ".".repeat(dots),
                    ports
                );
            }
            None => {
                println!("{}{}", line.prefix, line.name);
            }
        }
    }
}

fn allocate_port(
    config: &Path,
    role: &str,
    explicit_workload_id: Option<&str>,
) -> Result<(AllocationIdentity, i64, bool), String> {
    let identity = allocation_identity(explicit_workload_id)?;
    let (port, created) = port_registry::allocate(config, &identity.key, role, identity.logical)?;
    Ok((identity, port, created))
}

fn describe_assignment(identity: &AllocationIdentity, role: &str) -> String {
    let subject = if identity.logical {
        format!("Workload {}", identity.key)
    } else {
        identity.key.clone()
    };
    if role == DEFAULT_ROLE {
        subject
    } else {
        format!("{subject} ({role})")
    }
}

fn cmd_register(config: &Path, role: &str, explicit_workload_id: Option<&str>) {
    let (identity, port, created) =
        allocate_port(config, role, explicit_workload_id).unwrap_or_else(exit_registry_error);

    let action = if created {
        "Registered"
    } else {
        "Already registered:"
    };
    eprintln!(
        "{} {} → port {}",
        action,
        describe_assignment(&identity, role),
        port
    );
    println!("{}", port);
}

fn resolve_dir(doc: &DocumentMut, arg: &str) -> Option<String> {
    let table = doc["ports"].as_table()?;

    if arg == "." {
        let cwd = cwd_string();
        if table.contains_key(&cwd) {
            return Some(cwd);
        }
        eprintln!("Current directory is not registered: {}", cwd);
        return None;
    }

    // Try as directory name suffix
    let matches: Vec<&str> = table
        .iter()
        .map(|(k, _)| k)
        .filter(|k| k.ends_with(&format!("/{}", arg)))
        .collect();

    match matches.len() {
        0 => {
            eprintln!("No mapping found matching '{}'", arg);
            None
        }
        1 => Some(matches[0].to_string()),
        _ => {
            eprintln!("Ambiguous match for '{}'. Matching directories:", arg);
            for m in &matches {
                eprintln!("  {}", m);
            }
            None
        }
    }
}

fn cmd_delete(config: &Path, arg: &str, role: Option<&str>) {
    if let Ok(port_num) = arg.parse::<i64>() {
        let (dir, found_role) = update_config(config, |doc| {
            ensure_ports_table(doc);
            let mut found = None;
            if let Some(table) = doc["ports"].as_table() {
                for (dir, dir_value) in table.iter() {
                    if let Some(dir_table) = dir_value.as_table() {
                        for (r, port_value) in dir_table.iter() {
                            if port_value.as_integer() == Some(port_num) {
                                found = Some((dir.to_string(), r.to_string()));
                            }
                        }
                    }
                }
            }
            let Some((dir, found_role)) = found else {
                eprintln!("No mapping found for port {}", port_num);
                process::exit(1);
            };
            doc["ports"][&dir]
                .as_table_mut()
                .unwrap()
                .remove(&found_role);
            if doc["ports"][&dir].as_table().is_none_or(|t| t.is_empty()) {
                doc["ports"].as_table_mut().unwrap().remove(&dir);
            }
            route_cache::remove_for_registration(doc, &dir, Some(&found_role));
            (dir, found_role)
        });
        if found_role == DEFAULT_ROLE {
            eprintln!("Removed {} (was port {})", dir, port_num);
        } else {
            eprintln!("Removed {} ({}) (was port {})", dir, found_role, port_num);
        }
        return;
    }

    if let Some(role) = role {
        let (key, port) = update_config(config, |doc| {
            ensure_ports_table(doc);
            let key = resolve_dir(doc, arg).unwrap_or_else(|| process::exit(1));
            let Some(port) = doc["ports"]
                .as_table()
                .and_then(|t| t.get(&key))
                .and_then(|v| v.as_table())
                .and_then(|t| t.get(role))
                .and_then(|v| v.as_integer())
            else {
                eprintln!("No {} port registered for {}", role, key);
                process::exit(1);
            };
            doc["ports"][&key].as_table_mut().unwrap().remove(role);
            if doc["ports"][&key].as_table().is_none_or(|t| t.is_empty()) {
                doc["ports"].as_table_mut().unwrap().remove(&key);
            }
            route_cache::remove_for_registration(doc, &key, Some(role));
            (key, port)
        });
        if role == DEFAULT_ROLE {
            eprintln!("Removed {} (was port {})", key, port);
        } else {
            eprintln!("Removed {} ({}) (was port {})", key, role, port);
        }
    } else {
        let (key, ports) = update_config(config, |doc| {
            ensure_ports_table(doc);
            let key = resolve_dir(doc, arg).unwrap_or_else(|| process::exit(1));
            let ports: Vec<(String, i64)> = doc["ports"]
                .as_table()
                .and_then(|t| t.get(&key))
                .and_then(|v| v.as_table())
                .map(|t| {
                    t.iter()
                        .filter_map(|(r, v)| v.as_integer().map(|p| (r.to_string(), p)))
                        .collect()
                })
                .unwrap_or_default();
            doc["ports"].as_table_mut().unwrap().remove(&key);
            route_cache::remove_for_registration(doc, &key, None);
            (key, ports)
        });
        for (role, port) in &ports {
            if role == DEFAULT_ROLE {
                eprintln!("Removed {} (was port {})", key, port);
            } else {
                eprintln!("Removed {} ({}) (was port {})", key, role, port);
            }
        }
    }
}

fn cmd_port(config: &Path, role: &str, explicit_workload_id: Option<&str>) {
    let (identity, port, created) =
        allocate_port(config, role, explicit_workload_id).unwrap_or_else(exit_registry_error);
    if created {
        eprintln!(
            "Registered {} → port {}",
            describe_assignment(&identity, role),
            port
        );
    }
    println!("{}", port);
}

fn open_url(url: &str) -> std::io::Result<process::Child> {
    if cfg!(target_os = "macos") {
        process::Command::new("open").arg(url).spawn()
    } else if cfg!(target_os = "windows") {
        process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
    } else {
        process::Command::new("xdg-open").arg(url).spawn()
    }
}

fn cmd_open(config: &Path, role: &str) {
    let cwd_str = cwd_string();
    let doc = read_config(config);

    let port = doc["ports"]
        .as_table()
        .and_then(|t| t.get(&cwd_str))
        .and_then(|v| v.as_table())
        .and_then(|t| t.get(role))
        .and_then(|v| v.as_integer());

    let port = match port {
        Some(p) => p,
        None => {
            if role == DEFAULT_ROLE {
                eprintln!("No port registered for {}", cwd_str);
            } else {
                eprintln!("No {} port registered for {}", role, cwd_str);
            }
            eprintln!(
                "Run 'phx-port register{}' first.",
                if role == DEFAULT_ROLE {
                    String::new()
                } else {
                    format!(" {}", role)
                }
            );
            process::exit(1);
        }
    };

    let url = format!("http://localhost:{}", port);
    eprintln!("Opening {}", url);

    if let Err(e) = open_url(&url) {
        eprintln!("Failed to open browser: {}", e);
        process::exit(1);
    }
}

pub(crate) fn is_port_open(port: i64) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], port as u16).into();
    TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok()
}

struct RunningProject {
    dir: String,
    role: String,
    port: i64,
    hostnames: Vec<String>,
}

fn scheme_for_role(role: &str) -> &'static str {
    if role == "https" { "https" } else { "http" }
}

fn get_running_projects(config: &Path) -> Vec<RunningProject> {
    let doc = read_config(config);
    let mut hostnames_by_backend: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();

    if let Some(routes) = doc.get("discovered_routes").and_then(|v| v.as_table()) {
        for (hostname, route_value) in routes {
            let Some(route) = route_value.as_table() else {
                continue;
            };
            let Some(project) = route.get("project").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(role) = route.get("role").and_then(|v| v.as_str()) else {
                continue;
            };
            if route
                .get("certificate_fingerprint")
                .and_then(|v| v.as_str())
                .is_none()
            {
                continue;
            }
            if let Ok(hostname) = tls_client_hello::normalize_hostname(hostname) {
                hostnames_by_backend
                    .entry((project.to_string(), role.to_string()))
                    .or_default()
                    .insert(hostname);
            }
        }
    }

    let table = match doc.get("ports").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let mut running = Vec::new();
    for (dir, dir_value) in table.iter() {
        if let Some(dir_table) = dir_value.as_table() {
            for (role, port_value) in dir_table.iter() {
                if let Some(port) = port_value.as_integer()
                    && is_port_open(port)
                {
                    running.push(RunningProject {
                        dir: dir.to_string(),
                        role: role.to_string(),
                        port,
                        hostnames: hostnames_by_backend
                            .remove(&(dir.to_string(), role.to_string()))
                            .map(BTreeSet::into_iter)
                            .unwrap_or_default()
                            .collect(),
                    });
                }
            }
        }
    }
    running.sort_by_key(|r| r.port);
    running
}

fn cmd_running(config: &Path) {
    let running = get_running_projects(config);
    if running.is_empty() {
        eprintln!("No registered projects are currently running.");
        return;
    }
    for r in &running {
        let scheme = scheme_for_role(&r.role);
        if r.role == DEFAULT_ROLE {
            println!("  {scheme}://localhost:{:<5}  {}", r.port, r.dir);
        } else {
            println!(
                "  {scheme}://localhost:{:<5}  {} ({})",
                r.port, r.dir, r.role
            );
        }
    }
}

fn build_discover_html(projects: &[RunningProject]) -> String {
    let mut items = String::new();
    if projects.is_empty() {
        items.push_str(
            "    <li class=\"empty\">No projects are currently running. Refresh to check again.</li>\n",
        );
    } else {
        for p in projects {
            let name = std::path::Path::new(&p.dir)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&p.dir);
            let role_suffix = if p.role == DEFAULT_ROLE {
                String::new()
            } else {
                format!(" <span class=\"role\">({})</span>", escape_html(&p.role))
            };
            let local_scheme = scheme_for_role(&p.role);
            items.push_str("    <li>");
            items.push_str(&format!(
                "<div class=\"project\"><strong>{name}{role}</strong>\
                 <div class=\"dir\">{dir}</div></div>\
                 <div class=\"links\">\
                 <a class=\"endpoint local\" href=\"{local_scheme}://localhost:{port}\">\
                 {local_scheme}://localhost:{port}</a>",
                port = p.port,
                name = escape_html(name),
                role = role_suffix,
                dir = escape_html(&p.dir),
            ));
            for hostname in &p.hostnames {
                let hostname = escape_html(hostname);
                items.push_str(&format!(
                    "<a class=\"endpoint tls\" href=\"https://{hostname}/\">\
                     https://{hostname}/</a>"
                ));
            }
            items.push_str("</div></li>\n");
        }
    }

    let template = r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>phx-port discover</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       background: #1a1a2e; color: #eee; padding: 2rem; min-height: 100vh; }
h1 { font-size: 1.4rem; margin-bottom: 1.5rem; color: #e94560; }
ul { list-style: none; }
li { margin-bottom: 0.75rem; padding: 0.9rem 1rem; background: #16213e;
     border-radius: 6px; }
.project { margin-bottom: 0.65rem; }
.links { display: flex; flex-wrap: wrap; gap: 0.45rem; }
.endpoint { display: inline-block; padding: 0.45rem 0.65rem; background: #0f3460;
            border-radius: 4px; color: #eee; text-decoration: none;
            transition: background 0.2s; font-family: ui-monospace, monospace;
            font-size: 0.85rem; }
.endpoint:hover { background: #16518f; }
.endpoint.tls { color: #9ee6b8; }
.dir { color: #888; font-size: 0.85rem; margin-top: 0.25rem; }
.role { color: #aaa; }
.empty { color: #888; padding: 0.75rem 1rem; }
footer { margin-top: 2rem; color: #555; font-size: 0.8rem; }
</style></head>
<body>
<h1>&#128268; phx-port &mdash; running projects</h1>
<ul>
ITEMS_PLACEHOLDER</ul>
<footer>Click a project to open it. This page will close automatically.</footer>
<script>
document.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => navigator.sendBeacon('/shutdown'));
});
(function poll() {
    setTimeout(async () => {
        try { await fetch('/ping'); poll(); }
        catch {
            document.querySelectorAll('a').forEach(a => a.removeAttribute('href'));
            document.querySelector('footer').textContent =
                'The discover server has closed. This list may be out of date.';
            document.body.style.opacity = '0.5';
        }
    }, 3000);
})();
</script>
</body>
</html>"#;

    template.replace("ITEMS_PLACEHOLDER", &items)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn cmd_discover(config: &Path) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| {
        eprintln!("Failed to start server: {}", e);
        process::exit(1);
    });
    listener.set_nonblocking(true).unwrap_or_else(|e| {
        eprintln!("Failed to configure server: {}", e);
        process::exit(1);
    });

    let server_port = listener.local_addr().unwrap().port();
    let server_url = format!("http://localhost:{}", server_port);
    let deadline = Instant::now() + Duration::from_secs(5 * 60);

    eprintln!("Serving project list at {}", server_url);
    eprintln!("Will auto-close after 5 minutes. Press Ctrl+C to close sooner.");

    if let Err(e) = open_url(&server_url) {
        eprintln!("Failed to open browser: {}", e);
    }

    loop {
        if Instant::now() >= deadline {
            eprintln!("No selection made — timed out after 5 minutes.");
            break;
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = [0u8; 4096];
                let n = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                if path == "/favicon.ico" {
                    let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    continue;
                }

                if path == "/ping" {
                    let response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    continue;
                }

                if path == "/shutdown" {
                    let response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    drop(stream);
                    break;
                }

                let running = get_running_projects(config);
                let html = build_discover_html(&running);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(_) => break,
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = config_path();

    match args.first().map(|s| s.as_str()) {
        Some("--version" | "-V") => {
            println!("phx-port {}", VERSION);
        }
        Some("--help" | "-h") => {
            println!("{}", HELP);
        }
        Some("list") => {
            let mut flat = false;
            let mut port_only = false;
            for arg in args.iter().skip(1) {
                match arg.as_str() {
                    "--flat" => flat = true,
                    "--port-only" => port_only = true,
                    other => {
                        eprintln!("Unknown argument for 'list': {}", other);
                        process::exit(1);
                    }
                }
            }
            if flat {
                cmd_list(&config);
            } else {
                cmd_list_tree(&config, !port_only);
            }
        }
        Some("register") => {
            let (role, workload_id) =
                parse_allocation_args(&args[1..]).unwrap_or_else(exit_registry_error);
            cmd_register(&config, &role, workload_id.as_deref());
        }
        Some("delete") => {
            if let Some(target) = args.get(1) {
                let role = args.get(2).map(|s| s.as_str());
                cmd_delete(&config, target, role);
            } else {
                eprintln!("Usage: phx-port delete <port|name|.> [role]");
                process::exit(1);
            }
        }
        Some("open" | "launch") => {
            let role = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_ROLE);
            cmd_open(&config, role);
        }
        Some("running") => {
            cmd_running(&config);
        }
        Some("discover") => {
            cmd_discover(&config);
        }
        Some("daemon") => {
            let daemon_config = match ingress_limits::DaemonConfig::parse(&args[1..]) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("{error}");
                    eprintln!("{}", ingress_limits::DAEMON_USAGE);
                    process::exit(1);
                }
            };
            if let Err(error) = proxy::run(daemon_config) {
                eprintln!("TLS proxy failed: {error}");
                process::exit(1);
            }
        }
        Some("proxy") => match args.get(1).map(String::as_str) {
            Some("status") if args.len() == 2 => match proxy::query_control("STATUS") {
                Ok(response) => print!("{response}"),
                Err(error) => {
                    eprintln!("{error}");
                    process::exit(1);
                }
            },
            Some("routes") if args.len() == 2 => match proxy::query_control("ROUTES") {
                Ok(response) => print!("{response}"),
                Err(_) => route_cache::print(&config),
            },
            Some("stop") if args.len() == 2 => match proxy::query_control("STOP") {
                Ok(response) => print!("{response}"),
                Err(error) => {
                    eprintln!("{error}");
                    process::exit(1);
                }
            },
            Some("install-service") if args.len() == 2 => match systemd_service::install(&config) {
                Ok(path) => println!("Installed and started {}", path.display()),
                Err(error) => {
                    eprintln!("Failed to install systemd user service: {error}");
                    process::exit(1);
                }
            },
            Some("uninstall-service") if args.len() == 2 => match systemd_service::uninstall() {
                Ok(path) => println!("Stopped and removed {}", path.display()),
                Err(error) => {
                    eprintln!("Failed to uninstall systemd user service: {error}");
                    process::exit(1);
                }
            },
            _ => {
                eprintln!(
                    "Usage: phx-port proxy <status|routes|stop|install-service|uninstall-service>"
                );
                process::exit(1);
            }
        },
        Some("--workload-id") => {
            let (role, workload_id) =
                parse_allocation_args(&args).unwrap_or_else(exit_registry_error);
            cmd_port(&config, &role, workload_id.as_deref());
        }
        Some(other) if other.starts_with('-') => {
            eprintln!("Unknown option: {}", other);
            eprintln!();
            eprintln!("{}", HELP);
            process::exit(1);
        }
        Some(_) => {
            if std::io::stdout().is_terminal() {
                let unknown: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                eprintln!("Unknown command: {}", unknown.join(" "));
                eprintln!();
                eprintln!("{}", HELP);
                process::exit(1);
            } else {
                let (role, workload_id) =
                    parse_allocation_args(&args).unwrap_or_else(exit_registry_error);
                cmd_port(&config, &role, workload_id.as_deref());
            }
        }

        None => {
            if std::io::stdout().is_terminal() {
                println!("{}", HELP);
            } else {
                cmd_port(&config, DEFAULT_ROLE, None);
            }
        }
    }
}
