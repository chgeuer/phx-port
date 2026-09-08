use super::{EndpointIdentity, remove_owned_endpoint};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_ENDPOINTS: usize = 1024;
const RETRY_INTERVAL: Duration = Duration::from_secs(1);
static REGISTRY: Registry = Registry::new(MAX_ENDPOINTS);

pub(super) fn register(path: PathBuf) -> Result<EndpointCleanup, String> {
    REGISTRY.register(path)
}

pub(super) fn drain_pending() -> Result<usize, String> {
    REGISTRY.drain_pending()
}

pub(super) struct EndpointCleanup {
    entry: Arc<Entry>,
}

impl EndpointCleanup {
    pub(super) fn lock_path(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.entry.lock_path()
    }

    pub(super) fn set_identity(&self, identity: EndpointIdentity) -> Result<(), String> {
        self.entry
            .state
            .lock()
            .map_err(|_| "handoff endpoint cleanup lock poisoned")?
            .identity = Some(identity);
        Ok(())
    }

    pub(super) fn request(&self) {
        self.entry.closed.store(true, Ordering::Release);
    }

    pub(super) fn is_closed(&self) -> bool {
        self.entry.closed.load(Ordering::Acquire)
    }

    pub(super) fn finish(&self) -> Result<(), String> {
        self.request();
        self.entry.finish()
    }
}

impl Drop for EndpointCleanup {
    fn drop(&mut self) {
        self.request();
    }
}

struct Entry {
    path: Arc<EndpointPath>,
    closed: AtomicBool,
    finished: AtomicBool,
    state: Mutex<CleanupState>,
}

struct EndpointPath {
    path: PathBuf,
    lock: Mutex<()>,
}

#[derive(Default)]
struct CleanupState {
    identity: Option<EndpointIdentity>,
    retry_at: Option<Instant>,
    warned: bool,
}

impl Entry {
    fn lock_path(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.path
            .lock
            .lock()
            .map_err(|_| "handoff endpoint path lock poisoned".to_string())
    }

    fn finish(&self) -> Result<(), String> {
        let _path = self.lock_path()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "handoff endpoint cleanup lock poisoned")?;
        self.finish_locked(&mut state)
    }

    fn finish_locked(&self, state: &mut CleanupState) -> Result<(), String> {
        if self.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        // Only dirty-I/O callers take this lock. Keep the identity check and
        // unlink serialized with explicit close and same-path startup.
        let result = match state.identity {
            Some(identity) => remove_owned_endpoint(&self.path.path, identity),
            None => Ok(()),
        };
        match result {
            Ok(()) => {
                self.finished.store(true, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                state.retry_at = Some(Instant::now() + RETRY_INTERVAL);
                Err(format!(
                    "cannot clean up handoff endpoint: {:?}",
                    error.kind()
                ))
            }
        }
    }

    fn retry(&self, now: Instant) -> Result<usize, String> {
        let _path = self.lock_path()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "handoff endpoint cleanup lock poisoned")?;
        if state.retry_at.is_some_and(|deadline| now < deadline) {
            return Ok(0);
        }
        if self.finish_locked(&mut state).is_err() && !state.warned {
            state.warned = true;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}

struct Registry {
    entries: Mutex<Vec<Arc<Entry>>>,
    capacity: usize,
}

impl Registry {
    const fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            capacity,
        }
    }

    fn register(&self, path: PathBuf) -> Result<EndpointCleanup, String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "handoff cleanup registry lock poisoned")?;
        entries.retain(|entry| !entry.finished.load(Ordering::Acquire));
        if entries.len() >= self.capacity {
            return Err("handoff endpoint cleanup capacity exhausted".to_string());
        }
        let predecessors: Vec<_> = entries
            .iter()
            .filter(|entry| entry.path.path == path)
            .cloned()
            .collect();
        let path = predecessors.first().map_or_else(
            || {
                Arc::new(EndpointPath {
                    path,
                    lock: Mutex::new(()),
                })
            },
            |entry| Arc::clone(&entry.path),
        );
        let entry = Arc::new(Entry {
            path,
            closed: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            state: Mutex::new(CleanupState::default()),
        });
        entries.push(Arc::clone(&entry));
        drop(entries);
        let endpoint = EndpointCleanup { entry };
        for predecessor in predecessors {
            if predecessor.closed.load(Ordering::Acquire) {
                predecessor.finish()?;
            }
        }
        Ok(endpoint)
    }

    fn drain_pending(&self) -> Result<usize, String> {
        let pending: Vec<_> = self
            .entries
            .lock()
            .map_err(|_| "handoff cleanup registry lock poisoned")?
            .iter()
            .filter(|entry| {
                entry.closed.load(Ordering::Acquire) && !entry.finished.load(Ordering::Acquire)
            })
            .cloned()
            .collect();
        let mut failures = 0;
        for entry in pending {
            failures += entry.retry(Instant::now())?;
        }
        self.entries
            .lock()
            .map_err(|_| "handoff cleanup registry lock poisoned")?
            .retain(|entry| !entry.finished.load(Ordering::Acquire));
        Ok(failures)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ENDPOINTS, RETRY_INTERVAL, Registry};
    use crate::{EndpointIdentity, create_listener_socket};
    use nix::sys::socket::{UnixAddr, bind};
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn live_and_pending_endpoints_share_a_hard_capacity_limit() {
        let registry = Registry::new(MAX_ENDPOINTS);
        let mut endpoints: Vec<_> = (0..MAX_ENDPOINTS)
            .map(|index| registry.register(format!("{index}.sock").into()).unwrap())
            .collect();
        assert!(registry.register("overflow.sock".into()).is_err());

        drop(endpoints.pop());
        assert!(registry.register("overflow.sock".into()).is_err());
        assert_eq!(registry.drain_pending().unwrap(), 0);
        let replacement = registry.register("replacement.sock".into()).unwrap();
        assert!(registry.register("overflow.sock".into()).is_err());

        drop((endpoints, replacement));
        assert_eq!(registry.drain_pending().unwrap(), 0);
        assert!(registry.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn cleanup_failure_is_reported_once_and_holds_capacity_until_success() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let registry = Registry::new(1);
        let directory = tempdir().unwrap();
        let path = directory.path().join("handoff.sock");
        let cleanup = registry.register(path.clone()).unwrap();
        let listener = create_listener_socket().unwrap();
        bind(listener.as_raw_fd(), &UnixAddr::new(&path).unwrap()).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        cleanup
            .set_identity(EndpointIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500)).unwrap();
        cleanup.request();

        let failures = registry.drain_pending();
        let before_close = Instant::now();
        let repeated_close = cleanup.finish();
        let after_close = Instant::now();
        let retry_at = cleanup.entry.state.lock().unwrap().retry_at.unwrap();
        let repeated_poll = registry.drain_pending();
        let saturated = registry.register("next.sock".into()).is_err();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(failures.unwrap(), 1);
        assert!(repeated_close.unwrap_err().contains("PermissionDenied"));
        assert_eq!(repeated_poll.unwrap(), 0);
        assert!(saturated);
        assert!(path.try_exists().unwrap());
        assert!(retry_at >= before_close + RETRY_INTERVAL);
        assert!(retry_at <= after_close + RETRY_INTERVAL);
        let calls = crate::tests::CALLBACK_FILESYSTEM_CALLS.get();
        assert_eq!(
            cleanup
                .entry
                .retry(retry_at - Duration::from_nanos(1))
                .unwrap(),
            0
        );
        assert_eq!(crate::tests::CALLBACK_FILESYSTEM_CALLS.get(), calls);
        assert!(path.try_exists().unwrap());
        assert_eq!(cleanup.entry.retry(retry_at).unwrap(), 0);
        assert!(!path.try_exists().unwrap());
        assert_eq!(registry.drain_pending().unwrap(), 0);
        assert!(registry.register("next.sock".into()).is_ok());
    }

    #[test]
    fn callbacks_do_not_wait_for_cleanup_io_or_take_the_registry_lock() {
        let registry = Registry::new(2);
        let cleanup = registry.register("first.sock".into()).unwrap();
        let entry = std::sync::Arc::clone(&cleanup.entry);
        let state = entry.state.lock().unwrap();
        let entries = registry.entries.lock().unwrap();
        let path = entry.lock_path().unwrap();

        cleanup.request();
        drop(cleanup);
        assert!(entry.closed.load(std::sync::atomic::Ordering::Acquire));

        drop((state, entries, path));
        assert_eq!(registry.drain_pending().unwrap(), 0);
    }

    #[test]
    fn overlapping_same_path_lifecycles_share_the_cleanup_lock() {
        let registry = Registry::new(2);
        let first = registry.register("handoff.sock".into()).unwrap();
        let second = registry.register("handoff.sock".into()).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &first.entry.path,
            &second.entry.path
        ));
        let guard = first.lock_path().unwrap();
        assert!(second.entry.path.lock.try_lock().is_err());
        drop(guard);
        assert!(second.entry.path.lock.try_lock().is_ok());
    }
}
