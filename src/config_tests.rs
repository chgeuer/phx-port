use super::{read_config, update_config};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir;
use toml_edit::value;

#[test]
fn concurrent_updates_do_not_overwrite_each_other() {
    let directory = tempdir().unwrap();
    let path = Arc::new(directory.path().join("ports.toml"));
    let barrier = Arc::new(Barrier::new(12));
    let mut workers = Vec::new();

    for index in 0..12 {
        let path = Arc::clone(&path);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            update_config(&path, |document| {
                document["ports"][format!("/project-{index}")]["main"] = value(5000 + index);
            });
        }));
    }

    for worker in workers {
        worker.join().unwrap();
    }

    let document = read_config(&path);
    let ports = document["ports"].as_table().unwrap();
    assert_eq!(ports.len(), 12);
    for index in 0..12 {
        assert_eq!(
            ports[&format!("/project-{index}")]["main"].as_integer(),
            Some(5000 + index)
        );
    }
}
