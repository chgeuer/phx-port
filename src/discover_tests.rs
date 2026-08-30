use super::{
    RunningProject, build_discover_html, get_running_projects, read_config, update_config,
};
use crate::route_cache;
use std::net::TcpListener;
use tempfile::tempdir;
use toml_edit::value;

#[test]
fn joins_confirmed_hostnames_to_the_matching_live_registration() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("ports.toml");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = i64::from(listener.local_addr().unwrap().port());
    let closed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = i64::from(closed_listener.local_addr().unwrap().port());
    drop(closed_listener);

    update_config(&config, |document| {
        document["ports"]["/srv/contoso"] = toml_edit::table();
        document["ports"]["/srv/contoso"]["https"] = value(port);
        document["ports"]["/srv/fabrikam"] = toml_edit::table();
        document["ports"]["/srv/fabrikam"]["https"] = value(closed_port);
    });
    route_cache::store(&config, "www.contoso.com", "/srv/contoso", "https", "AA:BB");
    route_cache::store(
        &config,
        "www.fabrikam.com",
        "/srv/fabrikam",
        "https",
        "CC:DD",
    );
    assert_eq!(
        read_config(&config)["ports"]["/srv/contoso"]["https"].as_integer(),
        Some(port)
    );

    let projects = get_running_projects(&config);
    drop(listener);

    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].dir, "/srv/contoso");
    assert_eq!(projects[0].hostnames, ["www.contoso.com"]);
}

#[test]
fn renders_local_and_confirmed_tls_links_with_escaped_labels() {
    let html = build_discover_html(&[RunningProject {
        dir: "/srv/contoso<&".to_string(),
        role: "https".to_string(),
        port: 4401,
        hostnames: vec!["contoso.com".to_string(), "www.contoso.com".to_string()],
    }]);

    assert!(html.contains("href=\"http://localhost:4401\""));
    assert!(html.contains("href=\"https://contoso.com/\""));
    assert!(html.contains("href=\"https://www.contoso.com/\""));
    assert!(html.contains("/srv/contoso&lt;&amp;"));
    assert!(!html.contains("/srv/contoso<&"));
}
