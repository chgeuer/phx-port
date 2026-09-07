use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CONNECTION_WORKER_STACK_SIZE: usize = 2 * 1024 * 1024;

pub(crate) struct BoundedWorkerPool<Job> {
    sender: Option<SyncSender<Job>>,
    workers: Vec<JoinHandle<()>>,
}

impl<Job: Send + 'static> BoundedWorkerPool<Job> {
    pub(crate) fn start(
        name: &str,
        worker_count: usize,
        queue_capacity: usize,
        handler: impl Fn(Job) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        if worker_count == 0 {
            return Err("worker count must be greater than zero".to_string());
        }

        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let handler = Arc::new(handler);
        let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(worker_count);

        for index in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let handler = Arc::clone(&handler);
            let worker_name = format!("{name}-{index}");
            let worker = match thread::Builder::new()
                .name(worker_name)
                .stack_size(CONNECTION_WORKER_STACK_SIZE)
                .spawn(move || {
                    loop {
                        // The standard receiver is not cloneable; this lock covers dequeue only.
                        let job = {
                            let Ok(receiver) = receiver.lock() else {
                                return;
                            };
                            receiver.recv()
                        };
                        let Ok(job) = job else {
                            return;
                        };
                        if panic::catch_unwind(AssertUnwindSafe(|| handler(job))).is_err() {
                            eprintln!("Bounded connection worker recovered after a panicking job");
                        }
                    }
                }) {
                Ok(worker) => worker,
                Err(error) => {
                    drop(sender);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(format!(
                        "cannot start bounded connection worker pool: {error}"
                    ));
                }
            };
            workers.push(worker);
        }

        Ok(Self {
            sender: Some(sender),
            workers,
        })
    }

    pub(crate) fn sender(&self) -> SyncSender<Job> {
        self.sender
            .as_ref()
            .expect("worker pool sender requested after shutdown")
            .clone()
    }

    pub(crate) fn close(&mut self) {
        self.sender.take();
    }

    pub(crate) fn join(mut self) -> Result<(), String> {
        self.close();
        let mut panicked = false;
        for worker in self.workers {
            panicked |= worker.join().is_err();
        }

        if panicked {
            Err("bounded connection worker exited unexpectedly".to_string())
        } else {
            Ok(())
        }
    }

    pub(crate) fn join_until(mut self, deadline: Instant) -> Result<usize, String> {
        self.close();
        let mut panicked = false;
        loop {
            let mut index = 0;
            while index < self.workers.len() {
                if self.workers[index].is_finished() {
                    panicked |= self.workers.swap_remove(index).join().is_err();
                } else {
                    index += 1;
                }
            }
            if self.workers.is_empty() || Instant::now() >= deadline {
                break;
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5)),
            );
        }
        if panicked {
            Err("bounded connection worker exited unexpectedly".to_string())
        } else {
            // A stuck OS operation must not extend the process drain deadline.
            Ok(self.workers.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedWorkerPool;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, TrySendError};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    #[test]
    fn join_deadline_does_not_wait_for_a_blocked_job() {
        let (started, ready) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let wait = Mutex::new(wait);
        let (finished, done) = mpsc::sync_channel(1);
        let pool = BoundedWorkerPool::start("deadline-test", 1, 1, move |()| {
            started.send(()).unwrap();
            wait.lock().unwrap().recv().unwrap();
            finished.send(()).unwrap();
        })
        .unwrap();
        pool.sender().send(()).unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        assert_eq!(
            pool.join_until(started + Duration::from_millis(50))
                .unwrap(),
            1
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn worker_and_queue_bounds_are_exact() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let (started_sender, started_receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::channel();
        let pool = BoundedWorkerPool::start("bounded-test", 2, 1, {
            let gate = Arc::clone(&gate);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            move |()| {
                let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                maximum.fetch_max(current, Ordering::AcqRel);
                started_sender.send(()).unwrap();
                let (lock, available) = &*gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = available.wait(released).unwrap();
                }
                active.fetch_sub(1, Ordering::AcqRel);
                done_sender.send(()).unwrap();
            }
        })
        .unwrap();
        let sender = pool.sender();

        sender.send(()).unwrap();
        sender.send(()).unwrap();
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        sender.try_send(()).unwrap();
        assert!(matches!(sender.try_send(()), Err(TrySendError::Full(()))));
        assert_eq!(maximum.load(Ordering::Acquire), 2);

        let (lock, available) = &*gate;
        *lock.lock().unwrap() = true;
        available.notify_all();
        for _ in 0..3 {
            done_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        }

        drop(sender);
        pool.join().unwrap();
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(maximum.load(Ordering::Acquire), 2);
    }

    #[test]
    fn worker_survives_a_panicking_job() {
        let (done_sender, done_receiver) = mpsc::channel();
        let pool = BoundedWorkerPool::start("panic-test", 1, 1, move |job| {
            if job == 1 {
                panic!("simulated job panic");
            }
            done_sender.send(job).unwrap();
        })
        .unwrap();
        let sender = pool.sender();

        sender.send(1).unwrap();
        sender.send(2).unwrap();
        assert_eq!(
            done_receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            2
        );

        drop(sender);
        pool.join().unwrap();
    }
}
