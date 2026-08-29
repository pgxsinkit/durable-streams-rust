//! Fixed-size physical cleanup executor.
//!
//! This module deliberately performs one synchronous cleanup attempt only.
//! Coordinator admission, shared retirement tickets, and retries belong to C.

#![allow(dead_code)] // TODO(retirement-C): coordinator wiring makes this live.

use std::collections::VecDeque;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::store::{LocalCleanupDisposition, LocalCleanupMode, LocalCleanupOutcome, StreamState};

use super::{RetirementConfig, RetirementPriority, RESERVED_INTERACTIVE_CLEANUP_WORKERS};

pub(crate) type CleanupCallback = Arc<
    dyn Fn(&Arc<StreamState>, LocalCleanupMode) -> io::Result<LocalCleanupOutcome> + Send + Sync,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhysicalSubmitError {
    Full,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhysicalAttemptResult {
    Succeeded {
        reclaimed_local_bytes: u64,
        disposition: LocalCleanupDisposition,
    },
    Failed,
    Panicked,
    Cancelled,
}

pub(crate) struct PhysicalAttempt {
    result: oneshot::Receiver<PhysicalCompletion>,
}

pub(crate) struct PhysicalCompletion {
    pub(crate) result: PhysicalAttemptResult,
    pub(crate) duration: Duration,
}

impl PhysicalAttempt {
    pub(crate) async fn wait(self) -> PhysicalAttemptResult {
        self.wait_completion().await.result
    }

    pub(crate) async fn wait_completion(self) -> PhysicalCompletion {
        self.result.await.unwrap_or(PhysicalCompletion {
            result: PhysicalAttemptResult::Cancelled,
            duration: Duration::ZERO,
        })
    }
}

struct PhysicalJob {
    stream: Arc<StreamState>,
    mode: LocalCleanupMode,
    result: oneshot::Sender<PhysicalCompletion>,
}

struct QueueState {
    interactive: VecDeque<PhysicalJob>,
    proactive: VecDeque<PhysicalJob>,
    active_interactive: usize,
    active_proactive: usize,
    closed: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct PhysicalSnapshot {
    pub(crate) interactive_queued: usize,
    pub(crate) proactive_queued: usize,
    pub(crate) interactive_active: usize,
    pub(crate) proactive_active: usize,
    pub(crate) workers_live: usize,
    pub(crate) workers_total: usize,
    pub(crate) closed: bool,
}

struct Shared {
    queues: Mutex<QueueState>,
    wake: Condvar,
    interactive_capacity: usize,
    proactive_capacity: usize,
    workers_total: usize,
    workers_live: AtomicUsize,
    idle_announced: AtomicUsize,
    idle_observer: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

/// The queue drains during explicit shutdown. Drop only closes and cancels
/// queued jobs so it never blocks a runtime or panics while unwinding.
pub(crate) struct PhysicalExecutor {
    shared: Arc<Shared>,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl PhysicalExecutor {
    pub(crate) fn new(
        cleanup: CleanupCallback,
        config: &RetirementConfig,
    ) -> Result<Self, &'static str> {
        Self::build(cleanup, config, None)
    }

    fn build(
        cleanup: CleanupCallback,
        config: &RetirementConfig,
        idle_observer: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        if config.cleanup_workers == RESERVED_INTERACTIVE_CLEANUP_WORKERS
            && config.proactive_physical_capacity != 0
        {
            return Err("one reserved worker cannot drain a proactive queue");
        }
        let shared = Arc::new(Shared {
            queues: Mutex::new(QueueState {
                interactive: VecDeque::new(),
                proactive: VecDeque::new(),
                active_interactive: 0,
                active_proactive: 0,
                closed: false,
            }),
            wake: Condvar::new(),
            interactive_capacity: config.interactive_physical_capacity,
            proactive_capacity: config.proactive_physical_capacity,
            workers_total: config.cleanup_workers,
            workers_live: AtomicUsize::new(config.cleanup_workers),
            idle_announced: AtomicUsize::new(0),
            idle_observer,
        });
        let mut workers = Vec::with_capacity(config.cleanup_workers);
        for index in 0..config.cleanup_workers {
            let queues = shared.clone();
            let cleanup = cleanup.clone();
            workers.push(
                std::thread::Builder::new()
                    .name(format!("ds-retirement-cleanup-{index}"))
                    .spawn(move || worker_loop(index, queues, cleanup))
                    .expect("spawn fixed retirement cleanup worker"),
            );
        }
        Ok(Self {
            shared,
            workers: Mutex::new(workers),
        })
    }

    #[cfg(test)]
    fn new_with_idle_observer(
        cleanup: CleanupCallback,
        config: &RetirementConfig,
        observer: Arc<dyn Fn(usize) + Send + Sync>,
    ) -> Result<Self, &'static str> {
        Self::build(cleanup, config, Some(observer))
    }

    pub(crate) fn submit(
        &self,
        stream: Arc<StreamState>,
        priority: RetirementPriority,
        mode: LocalCleanupMode,
    ) -> Result<PhysicalAttempt, PhysicalSubmitError> {
        let (result, receiver) = oneshot::channel();
        let mut queues = lock_recover(&self.shared.queues);
        if queues.closed {
            return Err(PhysicalSubmitError::Closed);
        }
        let lane = match priority {
            RetirementPriority::Interactive => {
                (&mut queues.interactive, self.shared.interactive_capacity)
            }
            RetirementPriority::Proactive => {
                (&mut queues.proactive, self.shared.proactive_capacity)
            }
        };
        if lane.0.len() >= lane.1 {
            return Err(PhysicalSubmitError::Full);
        }
        lane.0.push_back(PhysicalJob {
            stream,
            mode,
            result,
        });
        match priority {
            RetirementPriority::Interactive => self.shared.wake.notify_one(),
            // Worker zero is reserved and cannot consume this lane. Wake every
            // waiter so at least one of workers 1..N observes the job.
            RetirementPriority::Proactive => self.shared.wake.notify_all(),
        }
        Ok(PhysicalAttempt { result: receiver })
    }

    /// Closes admission, drains already-admitted jobs, and joins every fixed
    /// worker without blocking Tokio's runtime thread.
    pub(crate) async fn shutdown(&self) {
        self.close_admission();
        let workers = lock_recover(&self.workers).drain(..).collect();
        tokio::task::spawn_blocking(move || join_workers(workers))
            .await
            .expect("retirement worker join task should not panic");
    }

    fn close_admission(&self) {
        let mut queues = lock_recover(&self.shared.queues);
        queues.closed = true;
        self.shared.wake.notify_all();
    }

    fn cancel_queued(&self) {
        let mut queues = lock_recover(&self.shared.queues);
        queues.closed = true;
        let interactive = std::mem::take(&mut queues.interactive);
        let proactive = std::mem::take(&mut queues.proactive);
        for job in interactive.into_iter().chain(proactive) {
            let _ = job.result.send(PhysicalCompletion {
                result: PhysicalAttemptResult::Cancelled,
                duration: Duration::ZERO,
            });
        }
        self.shared.wake.notify_all();
    }

    #[cfg(test)]
    fn queue_counts(&self) -> (usize, usize) {
        let queues = lock_recover(&self.shared.queues);
        (queues.interactive.len(), queues.proactive.len())
    }

    pub(crate) fn snapshot(&self) -> PhysicalSnapshot {
        let queues = lock_recover(&self.shared.queues);
        PhysicalSnapshot {
            interactive_queued: queues.interactive.len(),
            proactive_queued: queues.proactive.len(),
            interactive_active: queues.active_interactive,
            proactive_active: queues.active_proactive,
            workers_live: self.shared.workers_live.load(Ordering::Acquire),
            workers_total: self.shared.workers_total,
            closed: queues.closed,
        }
    }

    #[cfg(test)]
    pub(crate) fn worker_count(&self) -> usize {
        self.shared.workers_live.load(Ordering::Acquire)
    }
}

impl Drop for PhysicalExecutor {
    fn drop(&mut self) {
        self.cancel_queued();
        // Dropping JoinHandles detaches, but every idle worker has been woken
        // and exits. Explicit shutdown is the deterministic join boundary.
        lock_recover(&self.workers).clear();
    }
}

fn worker_loop(index: usize, shared: Arc<Shared>, cleanup: CleanupCallback) {
    loop {
        let job = {
            let mut queues = lock_recover(&shared.queues);
            loop {
                let job = if index == 0 {
                    queues
                        .interactive
                        .pop_front()
                        .map(|job| (job, RetirementPriority::Interactive))
                } else {
                    queues
                        .interactive
                        .pop_front()
                        .map(|job| (job, RetirementPriority::Interactive))
                        .or_else(|| {
                            queues
                                .proactive
                                .pop_front()
                                .map(|job| (job, RetirementPriority::Proactive))
                        })
                };
                if let Some(job) = job {
                    match job.1 {
                        RetirementPriority::Interactive => queues.active_interactive += 1,
                        RetirementPriority::Proactive => queues.active_proactive += 1,
                    }
                    break job;
                }
                if queues.closed {
                    shared.workers_live.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                if let Some(observer) = &shared.idle_observer {
                    let bit = 1usize << index;
                    if shared.idle_announced.fetch_or(bit, Ordering::AcqRel) & bit == 0 {
                        observer(index);
                    }
                }
                queues = shared
                    .wake
                    .wait(queues)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };
        let (job, priority) = job;
        let started = std::time::Instant::now();
        let result = match catch_unwind(AssertUnwindSafe(|| cleanup(&job.stream, job.mode))) {
            Ok(Ok(outcome)) => PhysicalAttemptResult::Succeeded {
                reclaimed_local_bytes: outcome.reclaimed_local_bytes,
                disposition: outcome.disposition,
            },
            Ok(Err(error)) => {
                if job.mode == LocalCleanupMode::Expiry {
                    crate::store::log_expiry_cleanup_failure(&job.stream, &error);
                }
                PhysicalAttemptResult::Failed
            }
            Err(_) => {
                if job.mode == LocalCleanupMode::Expiry {
                    let error = io::Error::other("cleanup callback panicked");
                    crate::store::log_expiry_cleanup_failure(&job.stream, &error);
                }
                PhysicalAttemptResult::Panicked
            }
        };
        let duration = started.elapsed();
        {
            let mut queues = lock_recover(&shared.queues);
            match priority {
                RetirementPriority::Interactive => {
                    queues.active_interactive = queues.active_interactive.saturating_sub(1)
                }
                RetirementPriority::Proactive => {
                    queues.active_proactive = queues.active_proactive.saturating_sub(1)
                }
            }
        }
        let _ = job.result.send(PhysicalCompletion { result, duration });
    }
}

fn join_workers(workers: Vec<std::thread::JoinHandle<()>>) {
    for worker in workers {
        let _ = worker.join();
    }
}

fn lock_recover<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retirement::DEFAULT_CLEANUP_WORKERS;
    use crate::store::{CreateResult, Store, StreamConfig};
    use crate::tier::TierConfig;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::mpsc;
    use std::time::Duration;

    fn stream_config() -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn store_stream(name: &str) -> (Arc<Store>, Arc<StreamState>, std::path::PathBuf) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ds-retirement-physical-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        let stream = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("stream create failed"),
        };
        (store, stream, directory)
    }

    fn config(interactive: usize, proactive: usize, workers: usize) -> RetirementConfig {
        RetirementConfig {
            interactive_physical_capacity: interactive,
            proactive_physical_capacity: proactive,
            physical_queue_capacity: interactive + proactive,
            cleanup_workers: workers,
            ..RetirementConfig::default()
        }
    }

    fn success() -> CleanupCallback {
        Arc::new(|_, _| Ok(LocalCleanupOutcome::default()))
    }

    fn create_stream(store: &Store, path: &str) -> Arc<StreamState> {
        match store.create(path, stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("stream create failed"),
        }
    }

    #[test]
    fn retirement_queue_physical_defaults_are_exact() {
        let config = RetirementConfig::default();
        assert_eq!(config.interactive_physical_capacity, 64);
        assert_eq!(config.proactive_physical_capacity, 960);
        assert_eq!(config.physical_queue_capacity, 1024);
        assert_eq!(config.cleanup_workers, 4);
        let executor = PhysicalExecutor::new(success(), &config).unwrap();
        assert_eq!(executor.worker_count(), DEFAULT_CLEANUP_WORKERS);
        drop(executor);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_physical_proactive_wakes_a_capable_idle_worker() {
        let (store, stream, directory) = store_stream("proactive-wake");
        let (idle_tx, idle_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            let name = std::thread::current().name().unwrap_or_default().to_owned();
            let index = name
                .rsplit('-')
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .expect("fixed cleanup worker name has an index");
            started_tx.send(index).unwrap();
            Ok(LocalCleanupOutcome::default())
        });
        let observer = Arc::new(move |index| idle_tx.send(index).unwrap());
        let executor = PhysicalExecutor::new_with_idle_observer(
            cleanup,
            &RetirementConfig::default(),
            observer,
        )
        .unwrap();
        let mut idle = Vec::new();
        for _ in 0..DEFAULT_CLEANUP_WORKERS {
            idle.push(idle_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        }
        idle.sort_unstable();
        assert_eq!(idle, vec![0, 1, 2, 3]);
        let attempt = executor
            .submit(
                stream,
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        assert_ne!(started_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
        assert!(matches!(
            attempt.wait().await,
            PhysicalAttemptResult::Succeeded { .. }
        ));
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_physical_lanes_fill_independently() {
        let (store, stream, directory) = store_stream("full");
        let (started_tx, started_rx) = mpsc::channel();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_gate = gate.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            started_tx.send(()).unwrap();
            let (lock, wake) = &*worker_gate;
            let mut released = lock_recover(lock);
            while !*released {
                released = wake
                    .wait(released)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            Ok(LocalCleanupOutcome::default())
        });
        let executor = PhysicalExecutor::new(cleanup, &config(1, 1, 2)).unwrap();
        let _ = executor
            .submit(
                stream.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        let _ = executor
            .submit(
                stream.clone(),
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let queued_interactive = executor
            .submit(
                stream.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        let queued_proactive = executor
            .submit(
                stream.clone(),
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        assert_eq!(executor.queue_counts(), (1, 1));
        assert!(matches!(
            executor.submit(
                stream.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry
            ),
            Err(PhysicalSubmitError::Full)
        ));
        assert!(matches!(
            executor.submit(
                stream,
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry
            ),
            Err(PhysicalSubmitError::Full)
        ));
        *lock_recover(&gate.0) = true;
        gate.1.notify_all();
        executor.shutdown().await;
        assert!(matches!(
            queued_interactive.wait().await,
            PhysicalAttemptResult::Succeeded { .. }
        ));
        assert!(matches!(
            queued_proactive.wait().await,
            PhysicalAttemptResult::Succeeded { .. }
        ));
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_physical_reserves_worker_and_prefers_interactive() {
        let (store, first, directory) = store_stream("priority");
        let second = create_stream(&store, "second");
        let interactive = create_stream(&store, "interactive");
        let (started_tx, started_rx) = mpsc::channel();
        let (idle_tx, idle_rx) = mpsc::channel();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_gate = gate.clone();
        let cleanup: CleanupCallback = Arc::new(move |stream, _| {
            started_tx.send(stream.id).unwrap();
            let (lock, wake) = &*worker_gate;
            let mut released = lock_recover(lock);
            while !*released {
                released = wake
                    .wait(released)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            Ok(LocalCleanupOutcome::default())
        });
        let observer = Arc::new(move |index| idle_tx.send(index).unwrap());
        let executor =
            PhysicalExecutor::new_with_idle_observer(cleanup, &config(2, 2, 2), observer).unwrap();
        let mut idle = vec![
            idle_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            idle_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        ];
        idle.sort_unstable();
        assert_eq!(idle, vec![0, 1]);
        let _ = executor
            .submit(
                first.clone(),
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            first.id
        );
        let _ = executor
            .submit(
                second,
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        let _ = executor
            .submit(
                interactive.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            interactive.id
        );
        assert_eq!(executor.queue_counts(), (0, 1));
        *lock_recover(&gate.0) = true;
        gate.1.notify_all();
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_physical_fifo_and_strong_arc_retention() {
        let (store, first, directory) = store_stream("fifo");
        let second = create_stream(&store, "second");
        let third = create_stream(&store, "third");
        let (started_tx, started_rx) = mpsc::channel();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_gate = gate.clone();
        let cleanup: CleanupCallback = Arc::new(move |stream, _| {
            started_tx.send(stream.id).unwrap();
            let (lock, wake) = &*worker_gate;
            let mut released = lock_recover(lock);
            while !*released {
                released = wake
                    .wait(released)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            Ok(LocalCleanupOutcome::default())
        });
        let executor = PhysicalExecutor::new(cleanup, &config(3, 0, 1)).unwrap();
        let _ = executor
            .submit(
                first.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            first.id
        );
        let _ = executor
            .submit(
                second.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        let _ = executor
            .submit(
                third.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        store.streams.remove("stream");
        let weak = Arc::downgrade(&first);
        drop(first);
        assert!(weak.upgrade().is_some());
        *lock_recover(&gate.0) = true;
        gate.1.notify_all();
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            second.id
        );
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            third.id
        );
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_physical_reports_error_panic_and_worker_survives() {
        let (store, stream, directory) = store_stream("failures");
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = calls.clone();
        let cleanup: CleanupCallback =
            Arc::new(
                move |_, _| match callback_calls.fetch_add(1, Ordering::AcqRel) {
                    0 => Err(io::Error::other("expected")),
                    1 => panic!("expected callback panic"),
                    _ => Ok(LocalCleanupOutcome {
                        reclaimed_local_bytes: 7,
                        ..LocalCleanupOutcome::default()
                    }),
                },
            );
        let executor = PhysicalExecutor::new(cleanup, &config(3, 0, 1)).unwrap();
        assert_eq!(
            executor
                .submit(
                    stream.clone(),
                    RetirementPriority::Interactive,
                    LocalCleanupMode::Expiry
                )
                .unwrap()
                .wait()
                .await,
            PhysicalAttemptResult::Failed
        );
        assert_eq!(
            executor
                .submit(
                    stream.clone(),
                    RetirementPriority::Interactive,
                    LocalCleanupMode::Expiry
                )
                .unwrap()
                .wait()
                .await,
            PhysicalAttemptResult::Panicked
        );
        assert_eq!(
            executor
                .submit(
                    stream,
                    RetirementPriority::Interactive,
                    LocalCleanupMode::Expiry
                )
                .unwrap()
                .wait()
                .await,
            PhysicalAttemptResult::Succeeded {
                reclaimed_local_bytes: 7,
                disposition: LocalCleanupDisposition::HardReaped,
            }
        );
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_physical_shutdown_drains_and_drop_is_nonblocking() {
        let (store, stream, directory) = store_stream("shutdown");
        let executor = PhysicalExecutor::new(success(), &config(2, 0, 1)).unwrap();
        let first = executor
            .submit(
                stream.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        let second = executor
            .submit(
                stream.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry,
            )
            .unwrap();
        executor.shutdown().await;
        assert!(matches!(
            first.wait().await,
            PhysicalAttemptResult::Succeeded { .. }
        ));
        assert!(matches!(
            second.wait().await,
            PhysicalAttemptResult::Succeeded { .. }
        ));
        assert_eq!(executor.worker_count(), 0);
        assert!(matches!(
            executor.submit(
                stream,
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry
            ),
            Err(PhysicalSubmitError::Closed)
        ));
        drop(executor);
        let drop_only = PhysicalExecutor::new(success(), &config(1, 0, 1)).unwrap();
        drop(drop_only);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }
}
