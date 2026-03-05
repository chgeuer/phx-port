use std::env;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process;
use toml_edit::{DocumentMut, value};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
phx-port — stable port assignments for Phoenix projects

USAGE:
    PORT=$(phx-port) iex -S mix phx.server

    phx-port --list         List all registered projects and ports
    phx-port --register     Register the current directory for a new port
    phx-port --delete <X>   Remove a mapping (X = port number, directory name, or '.')

When piped (e.g. in a script), prints the port for the current directory,
auto-registering if needed. Port 4000 is kept free.

Config: ~/.config/phx-ports.toml (override with PHX_PORT_CONFIG env var)";

fn config_path() -> PathBuf {
    if let Ok(custom) = env::var("PHX_PORT_CONFIG") {
        return PathBuf::from(custom);
    }
    let home = env::var("HOME").unwrap_or_else(|_| {
        eprintln!("Error: HOME environment variable not set");
        process::exit(1);
    });
    PathBuf::from(home).join(".config").join("phx-ports.toml")
}

fn read_config(path: &PathBuf) -> DocumentMut {
    if path.exists() {
        let content = fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {}", path.display(), e);
            process::exit(1);
        });
        content.parse::<DocumentMut>().unwrap_or_else(|e| {
            eprintln!("Error parsing {}: {}", path.display(), e);
            process::exit(1);
        })
    } else {
        "[ports]\n".parse::<DocumentMut>().unwrap()
    }
}

fn write_config(path: &PathBuf, doc: &DocumentMut) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Error creating {}: {}", parent.display(), e);
            process::exit(1);
        });
    }
    fs::write(path, doc.to_string()).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        process::exit(1);
    });
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

fn ensure_ports_table(doc: &mut DocumentMut) {
    if !doc.contains_table("ports") {
        doc["ports"] = toml_edit::table();
    }
}

fn next_port(doc: &DocumentMut) -> i64 {
    let max_port = doc["ports"]
        .as_table()
        .map(|t| t.iter().filter_map(|(_, v)| v.as_integer()).max())
        .flatten()
        .unwrap_or(4000);
    max_port + 1
}

fn cmd_list(config: &PathBuf) {
    let doc = read_config(config);
    if let Some(table) = doc.get("ports").and_then(|v| v.as_table()) {
        if table.is_empty() {
            eprintln!("No ports registered. Use --register or PORT=$(phx-port) to add one.");
            return;
        }
        // Collect and sort by port number
        let mut entries: Vec<(&str, i64)> = table
            .iter()
            .filter_map(|(k, v)| v.as_integer().map(|p| (k, p)))
            .collect();
        entries.sort_by_key(|(_, p)| *p);

        for (dir, port) in entries {
            println!("{:>5}  {}", port, dir);
        }
    } else {
        eprintln!("No ports registered.");
    }
}

fn cmd_register(config: &PathBuf) {
    let cwd_str = cwd_string();
    let mut doc = read_config(config);
    ensure_ports_table(&mut doc);

    if let Some(port) = doc["ports"]
        .as_table()
        .and_then(|t| t.get(&cwd_str))
        .and_then(|v| v.as_integer())
    {
        eprintln!("Already registered: {} → port {}", cwd_str, port);
        println!("{}", port);
        return;
    }

    let new_port = next_port(&doc);
    doc["ports"][&cwd_str] = value(new_port);
    write_config(config, &doc);
    eprintln!("Registered {} → port {}", cwd_str, new_port);
    println!("{}", new_port);
}

fn cmd_delete(config: &PathBuf, arg: &str) {
    let mut doc = read_config(config);
    ensure_ports_table(&mut doc);

    let resolve_target = |arg: &str| -> Option<String> {
        let table = doc["ports"].as_table()?;

        // "." means current directory
        if arg == "." {
            let cwd = cwd_string();
            if table.contains_key(&cwd) {
                return Some(cwd);
            }
            eprintln!("Current directory is not registered: {}", cwd);
            return None;
        }

        // Try as port number
        if let Ok(port_num) = arg.parse::<i64>() {
            for (k, v) in table.iter() {
                if v.as_integer() == Some(port_num) {
                    return Some(k.to_string());
                }
            }
            eprintln!("No mapping found for port {}", port_num);
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
    };

    if let Some(key) = resolve_target(arg) {
        let port = doc["ports"]
            .as_table()
            .and_then(|t| t.get(&key))
            .and_then(|v| v.as_integer())
            .unwrap_or(0);
        doc["ports"].as_table_mut().unwrap().remove(&key);
        write_config(config, &doc);
        eprintln!("Removed {} (was port {})", key, port);
    } else {
        process::exit(1);
    }
}

fn cmd_port(config: &PathBuf) {
    let cwd_str = cwd_string();
    let mut doc = read_config(config);
    ensure_ports_table(&mut doc);

    if let Some(port) = doc["ports"]
        .as_table()
        .and_then(|t| t.get(&cwd_str))
        .and_then(|v| v.as_integer())
    {
        println!("{}", port);
        return;
    }

    let new_port = next_port(&doc);
    doc["ports"][&cwd_str] = value(new_port);
    write_config(config, &doc);
    eprintln!("Registered {} → port {}", cwd_str, new_port);
    println!("{}", new_port);
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
        Some("--list" | "-l") => {
            cmd_list(&config);
        }
        Some("--register" | "-r") => {
            cmd_register(&config);
        }
        Some("--delete" | "-d") => {
            if let Some(target) = args.get(1) {
                cmd_delete(&config, target);
            } else {
                eprintln!("Usage: phx-port --delete <port|name|.>");
                process::exit(1);
            }
        }
        Some(other) => {
            eprintln!("Unknown option: {}", other);
            eprintln!("{}", HELP);
            process::exit(1);
        }
        None => {
            // No arguments: if interactive, show help; if piped, print port
            if std::io::stdout().is_terminal() {
                println!("{}", HELP);
            } else {
                cmd_port(&config);
            }
        }
    }
}
