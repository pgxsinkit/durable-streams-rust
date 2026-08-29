//! Bounded retirement coordinator with one supervised retry timer.
//!
//! This slice owns admission and scheduling only. Logical retirement is still
//! completed by the later handler-ordering slice.

// TODO(retirement-005): handler retirement wiring makes this coordinator live.
#![allow(dead_code)]

use std::cmp::{Ordering as CmpOrdering, Reverse};
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Instant, SystemTime};

use tokio::sync::{mpsc, Notify};

use crate::store::{LocalCleanupMode, StreamState};

use super::{
    retry_backoff, CleanupCallback, FirstAttemptCompletion, LogicalCompletion,
    PhysicalAttemptResult, PhysicalExecutor, PhysicalSubmitError, RetirementAdmission,
    RetirementConfig, RetirementPriority, RetirementReservation, RetirementTicket,
    TerminalCleanupCompletion, MAX_CLEANUP_ATTEMPTS,
};

/// The result of an admission attempt. Duplicate admissions return the exact
/// same level-triggered ticket as the original caller.
pub(crate) enum RetirementAdmissionResult {
    Ticket(RetirementTicket),
    Rejected(RetirementAdmission),
}

struct Job {
    stream: Arc<StreamState>,
    ticket: RetirementTicket,
    priority: RetirementPriority,
    mode: LocalCleanupMode,
}

impl Job {
    fn id(&self) -> u64 {
        self.stream.id
    }
}

struct JobRecord {
    job: Arc<Job>,
    active_attempt: Option<u8>,
    retry_scheduled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScheduledRetry {
    due: Instant,
    sequence: u64,
    id: u64,
}

impl Ord for ScheduledRetry {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.due
            .cmp(&other.due)
            .then_with(|| self.sequence.cmp(&other.sequence))
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialOrd for ScheduledRetry {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct CoordinatorState {
    jobs: HashMap<u64, JobRecord>,
    interactive_pending: VecDeque<Arc<Job>>,
    proactive_pending: VecDeque<Arc<Job>>,
    retries: BinaryHeap<Reverse<ScheduledRetry>>,
    active_interactive: usize,
    active_proactive: usize,
    next_retry_sequence: u64,
    closed: bool,
}

impl CoordinatorState {
    fn active_total(&self) -> usize {
        self.active_interactive + self.active_proactive
    }
}

struct WorkerEvent {
    id: u64,
    attempt: u8,
    result: PhysicalAttemptResult,
}

struct Inner {
    config: RetirementConfig,
    // Lock order is coordinator state, then a stream's retirement state. Both
    // are held only for synchronous bookkeeping; no code awaits while either
    // lock is held, and no reverse acquisition is allowed.
    state: Mutex<CoordinatorState>,
    notify: Notify,
    physical: PhysicalExecutor,
    events: mpsc::Sender<WorkerEvent>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    dispatch_observer: Option<Arc<dyn Fn(u64) + Send + Sync>>,
}

/// Admission plus one physical cleanup attempt per stream.
pub(crate) struct RetirementExecutor {
    inner: Arc<Inner>,
}

impl RetirementExecutor {
    pub(crate) fn new(
        cleanup: CleanupCallback,
        config: RetirementConfig,
    ) -> Result<Self, &'static str> {
        Self::build(cleanup, config, None)
    }

    fn build(
        cleanup: CleanupCallback,
        config: RetirementConfig,
        #[cfg(test)] dispatch_observer: Option<Arc<dyn Fn(u64) + Send + Sync>>,
        #[cfg(not(test))] _dispatch_observer: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        let physical = PhysicalExecutor::new(cleanup, &config)?;
        let (events, receiver) = mpsc::channel(config.coordinator_capacity);
        let inner = Arc::new(Inner {
            config,
            state: Mutex::new(CoordinatorState::default()),
            notify: Notify::new(),
            physical,
            events,
            task: Mutex::new(None),
            #[cfg(test)]
            dispatch_observer,
        });
        let task = tokio::spawn(coordinator(Arc::downgrade(&inner), receiver));
        *lock_recover(&inner.task) = Some(task);
        Ok(Self { inner })
    }

    #[cfg(test)]
    fn new_with_dispatch_observer(
        cleanup: CleanupCallback,
        config: RetirementConfig,
        observer: Arc<dyn Fn(u64) + Send + Sync>,
    ) -> Result<Self, &'static str> {
        Self::build(cleanup, config, Some(observer))
    }

    /// Admit one exact stream identity. This never blocks or starts fallback
    /// work when the coordinator's bounded queue is full.
    pub(crate) fn admit(
        &self,
        stream: Arc<StreamState>,
        priority: RetirementPriority,
        mode: LocalCleanupMode,
    ) -> RetirementAdmissionResult {
        let mut state = lock_recover(&self.inner.state);
        if state.closed {
            return RetirementAdmissionResult::Rejected(RetirementAdmission::ShuttingDown);
        }

        let ticket = {
            let mut retirement = stream.retirement_state();
            match retirement.reserve(Instant::now()) {
                RetirementReservation::Existing(ticket) => {
                    return RetirementAdmissionResult::Ticket(ticket);
                }
                RetirementReservation::CoolingDown => {
                    return RetirementAdmissionResult::Rejected(RetirementAdmission::CoolingDown);
                }
                RetirementReservation::New(ticket) => ticket,
            }
        };

        if state.jobs.len() >= self.inner.config.queue_capacity {
            stream.retirement_state().finish(&ticket);
            return RetirementAdmissionResult::Rejected(RetirementAdmission::QueueFull);
        }

        let job = Arc::new(Job {
            stream,
            ticket: ticket.clone(),
            priority,
            mode,
        });
        state.jobs.insert(
            job.id(),
            JobRecord {
                job: job.clone(),
                active_attempt: None,
                retry_scheduled: false,
            },
        );
        match priority {
            RetirementPriority::Interactive => state.interactive_pending.push_back(job),
            RetirementPriority::Proactive => state.proactive_pending.push_back(job),
        }
        drop(state);
        self.inner.notify.notify_one();
        RetirementAdmissionResult::Ticket(ticket)
    }

    /// The handler-ordering slice calls this after fencing, reader wakeup, and
    /// logical registry removal. Physical success intentionally does not imply
    /// this phase.
    pub(crate) fn complete_logical(&self, ticket: &RetirementTicket) {
        ticket.complete_logical(LogicalCompletion::Completed);
    }

    /// Cancels every retained ticket at a deterministic boundary, then drains
    /// the fixed physical pool and joins it away from Tokio's runtime thread.
    pub(crate) async fn shutdown(&self) {
        self.cancel_all();
        let task = lock_recover(&self.inner.task).take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        self.inner.physical.shutdown().await;
    }

    fn cancel_all(&self) {
        let jobs = {
            let mut state = lock_recover(&self.inner.state);
            if state.closed {
                return;
            }
            state.closed = true;
            state.interactive_pending.clear();
            state.proactive_pending.clear();
            state.retries.clear();
            state.active_interactive = 0;
            state.active_proactive = 0;
            std::mem::take(&mut state.jobs)
        };
        for (_, record) in jobs {
            let job = record.job;
            job.ticket.complete_logical(LogicalCompletion::Cancelled);
            job.ticket
                .complete_first_attempt(FirstAttemptCompletion::Cancelled);
            job.ticket
                .complete_terminal(TerminalCleanupCompletion::Cancelled);
            job.stream.retirement_state().finish(&job.ticket);
        }
        self.inner.notify.notify_waiters();
    }

    #[cfg(test)]
    fn active_counts(&self) -> (usize, usize) {
        let state = lock_recover(&self.inner.state);
        (state.active_interactive, state.active_proactive)
    }

    #[cfg(test)]
    fn pending_and_jobs(&self) -> (usize, usize, usize) {
        let state = lock_recover(&self.inner.state);
        (
            state.jobs.len(),
            state.interactive_pending.len(),
            state.proactive_pending.len(),
        )
    }

    #[cfg(test)]
    fn scheduled_retry_count(&self) -> usize {
        lock_recover(&self.inner.state).retries.len()
    }
}

impl Drop for RetirementExecutor {
    fn drop(&mut self) {
        self.cancel_all();
        if let Some(task) = lock_recover(&self.inner.task).take() {
            task.abort();
        }
        // PhysicalExecutor::drop only wakes workers and cancels unstarted jobs;
        // it intentionally does not join on the caller's runtime thread. A
        // cancellation may reach ticket observers before an already-running
        // synchronous cleanup callback returns.
    }
}

async fn coordinator(inner: Weak<Inner>, mut events: mpsc::Receiver<WorkerEvent>) {
    loop {
        let Some(inner) = inner.upgrade() else {
            return;
        };
        enqueue_due_retries(&inner);
        dispatch_ready(&inner);

        let notified = inner.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let next_retry = next_retry_deadline(&inner);
        if lock_recover(&inner.state).closed {
            return;
        }
        if let Some(due) = next_retry {
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => finish_attempt(&inner, event),
                    None => return,
                },
                _ = &mut notified => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(due)) => {},
            }
        } else {
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => finish_attempt(&inner, event),
                    None => return,
                },
                _ = &mut notified => {},
            }
        }
    }
}

fn enqueue_due_retries(inner: &Arc<Inner>) {
    let mut state = lock_recover(&inner.state);
    let now = Instant::now();
    while state.retries.peek().is_some_and(|retry| retry.0.due <= now) {
        let retry = state.retries.pop().expect("peeked retry").0;
        let job = match state.jobs.get_mut(&retry.id) {
            Some(record) if record.retry_scheduled => {
                record.retry_scheduled = false;
                record.job.clone()
            }
            _ => continue,
        };
        match job.priority {
            RetirementPriority::Interactive => state.interactive_pending.push_back(job),
            RetirementPriority::Proactive => state.proactive_pending.push_back(job),
        }
    }
}

fn next_retry_deadline(inner: &Inner) -> Option<Instant> {
    lock_recover(&inner.state)
        .retries
        .peek()
        .map(|retry| retry.0.due)
}

fn dispatch_ready(inner: &Arc<Inner>) {
    loop {
        let submitted = {
            let mut state = lock_recover(&inner.state);
            if state.closed {
                return;
            }
            let total = state.active_total();
            let job = if total < inner.config.coordinator_capacity {
                if let Some(job) = state.interactive_pending.pop_front() {
                    Some(job)
                } else if state.active_proactive < inner.config.proactive_coordinator_capacity {
                    state.proactive_pending.pop_front()
                } else {
                    None
                }
            } else {
                None
            };
            let Some(job) = job else { return };
            let Some(record) = state.jobs.get(&job.id()) else {
                continue;
            };
            if record.active_attempt.is_some() || record.retry_scheduled {
                continue;
            }

            #[cfg(test)]
            if let Some(observer) = &inner.dispatch_observer {
                observer(job.id());
            }

            match inner
                .physical
                .submit(job.stream.clone(), job.priority, job.mode)
            {
                Ok(attempt) => {
                    let attempt_number = job.stream.retirement_state().record_attempt();
                    state
                        .jobs
                        .get_mut(&job.id())
                        .expect("queued job remains admitted")
                        .active_attempt = Some(attempt_number);
                    match job.priority {
                        RetirementPriority::Interactive => state.active_interactive += 1,
                        RetirementPriority::Proactive => state.active_proactive += 1,
                    }
                    Some((job, attempt, attempt_number))
                }
                Err(PhysicalSubmitError::Full) => {
                    push_front(&mut state, job);
                    None
                }
                Err(PhysicalSubmitError::Closed) => {
                    settle_without_attempt(&mut state, job, false);
                    None
                }
            }
        };

        match submitted {
            Some((job, attempt, attempt_number)) => {
                let events = inner.events.clone();
                // At most coordinator_capacity waiter tasks exist: each is
                // created only after reserving an active coordinator slot and
                // finishes when one fixed physical attempt completes.
                tokio::spawn(async move {
                    let _ = events
                        .send(WorkerEvent {
                            id: job.id(),
                            attempt: attempt_number,
                            result: attempt.wait().await,
                        })
                        .await;
                });
            }
            None => return,
        }
    }
}

fn push_front(state: &mut CoordinatorState, job: Arc<Job>) {
    match job.priority {
        RetirementPriority::Interactive => state.interactive_pending.push_front(job),
        RetirementPriority::Proactive => state.proactive_pending.push_front(job),
    }
}

fn settle_without_attempt(state: &mut CoordinatorState, job: Arc<Job>, cancelled: bool) {
    state.jobs.remove(&job.id());
    if cancelled {
        job.ticket.complete_logical(LogicalCompletion::Cancelled);
        job.ticket
            .complete_first_attempt(FirstAttemptCompletion::Cancelled);
        job.ticket
            .complete_terminal(TerminalCleanupCompletion::Cancelled);
    } else {
        job.ticket
            .complete_first_attempt(FirstAttemptCompletion::Failed);
        job.ticket
            .complete_terminal(TerminalCleanupCompletion::Failed);
    }
    job.stream.retirement_state().finish(&job.ticket);
}

fn finish_attempt(inner: &Inner, event: WorkerEvent) {
    let outcome = {
        let mut state = lock_recover(&inner.state);
        let job = match state.jobs.get_mut(&event.id) {
            Some(record) if record.active_attempt == Some(event.attempt) => {
                record.active_attempt = None;
                record.job.clone()
            }
            _ => return,
        };
        match job.priority {
            RetirementPriority::Interactive => {
                state.active_interactive = state.active_interactive.saturating_sub(1)
            }
            RetirementPriority::Proactive => {
                state.active_proactive = state.active_proactive.saturating_sub(1)
            }
        }
        match event.result {
            PhysicalAttemptResult::Succeeded {
                reclaimed_local_bytes,
            } => {
                state.jobs.remove(&event.id);
                AttemptOutcome::Succeeded(job, reclaimed_local_bytes)
            }
            PhysicalAttemptResult::Failed | PhysicalAttemptResult::Panicked
                if event.attempt < MAX_CLEANUP_ATTEMPTS =>
            {
                state.next_retry_sequence = state.next_retry_sequence.wrapping_add(1);
                let due = Instant::now() + retry_backoff(event.attempt, inner.config.retry_base);
                let sequence = state.next_retry_sequence;
                state
                    .jobs
                    .get_mut(&event.id)
                    .expect("active record remains")
                    .retry_scheduled = true;
                state.retries.push(Reverse(ScheduledRetry {
                    due,
                    sequence,
                    id: event.id,
                }));
                AttemptOutcome::Retry(job)
            }
            PhysicalAttemptResult::Failed | PhysicalAttemptResult::Panicked => {
                state.jobs.remove(&event.id);
                AttemptOutcome::Failed(job)
            }
            PhysicalAttemptResult::Cancelled => {
                state.jobs.remove(&event.id);
                AttemptOutcome::Cancelled(job)
            }
        }
    };
    if event.attempt == 1 {
        match &outcome {
            AttemptOutcome::Succeeded(job, reclaimed_local_bytes) => job
                .ticket
                .complete_first_attempt(FirstAttemptCompletion::Succeeded {
                    reclaimed_local_bytes: *reclaimed_local_bytes,
                }),
            AttemptOutcome::Retry(job) | AttemptOutcome::Failed(job) => job
                .ticket
                .complete_first_attempt(FirstAttemptCompletion::Failed),
            AttemptOutcome::Cancelled(job) => job
                .ticket
                .complete_first_attempt(FirstAttemptCompletion::Cancelled),
        }
    }
    match outcome {
        AttemptOutcome::Succeeded(job, reclaimed_local_bytes) => {
            job.ticket
                .complete_terminal(TerminalCleanupCompletion::Succeeded {
                    reclaimed_local_bytes,
                });
            job.stream.retirement_state().finish(&job.ticket);
        }
        AttemptOutcome::Retry(_) => {}
        AttemptOutcome::Failed(job) => {
            job.ticket
                .complete_terminal(TerminalCleanupCompletion::Failed);
            job.stream.retirement_state().fail_terminal(
                &job.ticket,
                Instant::now(),
                SystemTime::now(),
                inner.config.cooldown,
            );
        }
        AttemptOutcome::Cancelled(job) => {
            job.ticket
                .complete_terminal(TerminalCleanupCompletion::Cancelled);
            job.stream.retirement_state().finish(&job.ticket);
        }
    }
    inner.notify.notify_one();
}

enum AttemptOutcome {
    Succeeded(Arc<Job>, u64),
    Retry(Arc<Job>),
    Failed(Arc<Job>),
    Cancelled(Arc<Job>),
}

fn lock_recover<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CreateResult, LocalCleanupOutcome, Store, StreamConfig};
    use crate::tier::TierConfig;
    use std::io;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex as StdMutex};
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
            "ds-retirement-coordinator-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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

    fn stream(store: &Store, path: &str) -> Arc<StreamState> {
        match store.create(path, stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("stream create failed"),
        }
    }

    fn config(queue: usize, coordinator: usize, proactive: usize) -> RetirementConfig {
        RetirementConfig {
            queue_capacity: queue,
            coordinator_capacity: coordinator,
            proactive_coordinator_capacity: proactive,
            interactive_physical_capacity: 8,
            proactive_physical_capacity: 8,
            physical_queue_capacity: 16,
            cleanup_workers: 4,
            ..RetirementConfig::default()
        }
    }

    fn retry_config(queue: usize, retry_base: Duration) -> RetirementConfig {
        RetirementConfig {
            retry_base,
            ..config(queue, 8, 0)
        }
    }

    fn callback() -> CleanupCallback {
        Arc::new(|_, _| Ok(LocalCleanupOutcome::default()))
    }

    fn ticket(result: RetirementAdmissionResult) -> RetirementTicket {
        match result {
            RetirementAdmissionResult::Ticket(ticket) => ticket,
            RetirementAdmissionResult::Rejected(reason) => {
                panic!("unexpected rejection: {reason:?}")
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_deduplicates_ticket_and_retains_stream() {
        let (store, stream, directory) = store_stream("dedup");
        let executor = RetirementExecutor::new(callback(), config(2, 8, 0)).unwrap();
        let first = ticket(executor.admit(
            stream.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        let duplicate = ticket(executor.admit(
            stream.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        ));
        assert!(first.same_identity(&duplicate));
        store.streams.remove("stream");
        let weak = Arc::downgrade(&stream);
        drop(stream);
        assert!(weak.upgrade().is_some());
        executor.complete_logical(&first);
        assert_eq!(first.wait_logical().await, LogicalCompletion::Completed);
        assert!(matches!(
            first.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_queue_full_rolls_back_reservation() {
        let (store, first, directory) = store_stream("full");
        let second = stream(&store, "second");
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let worker_gate = gate.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            let (lock, wake) = &*worker_gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = wake.wait(open).unwrap();
            }
            Ok(LocalCleanupOutcome::default())
        });
        let executor = RetirementExecutor::new(cleanup, config(1, 8, 0)).unwrap();
        let first_ticket = ticket(executor.admit(
            first,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert!(matches!(
            executor.admit(
                second.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry
            ),
            RetirementAdmissionResult::Rejected(RetirementAdmission::QueueFull)
        ));
        assert!(second.retirement_state().is_clean());
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(matches!(
            first_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        let retry = ticket(executor.admit(
            second,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert!(matches!(
            retry.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_reserves_interactive_capacity() {
        let (store, first, directory) = store_stream("reserve");
        let mut streams = vec![first];
        for index in 0..4 {
            streams.push(stream(&store, &format!("stream-{index}")));
        }
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let worker_gate = gate.clone();
        let started = Arc::new(AtomicUsize::new(0));
        let started_callback = started.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            started_callback.fetch_add(1, Ordering::AcqRel);
            let (lock, wake) = &*worker_gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = wake.wait(open).unwrap();
            }
            Ok(LocalCleanupOutcome::default())
        });
        let executor = RetirementExecutor::new(cleanup, config(8, 10, 2)).unwrap();
        for item in streams.iter().take(3) {
            let _ = ticket(executor.admit(
                item.clone(),
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry,
            ));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if executor.active_counts() == (0, 2) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("proactive cap should bound active work");
        let interactive = ticket(executor.admit(
            streams[3].clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if executor.active_counts().0 == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("interactive reserved slot should start");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if started.load(Ordering::Acquire) == 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all admitted cleanup callbacks should start");
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(matches!(
            interactive.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_prefers_interactive_and_keeps_fifo() {
        let (store, first, directory) = store_stream("fifo");
        let second = stream(&store, "second");
        let third = stream(&store, "third");
        let fourth = stream(&store, "fourth");
        let fifth = stream(&store, "fifth");
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let worker_gate = gate.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            let (lock, wake) = &*worker_gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = wake.wait(open).unwrap();
            }
            Ok(LocalCleanupOutcome::default())
        });
        let (dispatch_tx, mut dispatch_rx) = tokio::sync::mpsc::unbounded_channel();
        let observer = Arc::new(move |id| {
            let _ = dispatch_tx.send(id);
        });
        let executor =
            RetirementExecutor::new_with_dispatch_observer(cleanup, config(8, 10, 2), observer)
                .unwrap();
        let first_proactive = ticket(executor.admit(
            first.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        ));
        let second_proactive = ticket(executor.admit(
            second.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        ));
        assert_eq!(dispatch_rx.recv().await, Some(first.id));
        assert_eq!(dispatch_rx.recv().await, Some(second.id));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if executor.active_counts() == (0, 2) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("two proactive jobs should occupy the configured cap");
        let a = ticket(executor.admit(
            third.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        ));
        let b = ticket(executor.admit(
            fourth.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        let c = ticket(executor.admit(
            fifth.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert_eq!(dispatch_rx.recv().await, Some(fourth.id));
        assert_eq!(dispatch_rx.recv().await, Some(fifth.id));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert_eq!(dispatch_rx.recv().await, Some(third.id));
        for value in [&first_proactive, &second_proactive, &a, &b, &c] {
            let _ = value.wait_terminal().await;
        }
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_failure_and_shutdown_settle_every_phase() {
        let (store, failing, directory) = store_stream("settle");
        let failure: CleanupCallback = Arc::new(|_, _| Err(io::Error::other("expected")));
        let executor = RetirementExecutor::new(failure, retry_config(2, Duration::ZERO)).unwrap();
        let failed = ticket(executor.admit(
            failing,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert_eq!(
            failed.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        assert_eq!(
            failed.wait_terminal().await,
            TerminalCleanupCompletion::Failed
        );
        executor.complete_logical(&failed);
        assert_eq!(failed.wait_logical().await, LogicalCompletion::Completed);
        executor.shutdown().await;

        let pending = RetirementExecutor::new(callback(), config(2, 8, 0)).unwrap();
        let waiting = ticket(pending.admit(
            stream(&store, "pending"),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        pending.shutdown().await;
        assert_eq!(waiting.wait_logical().await, LogicalCompletion::Cancelled);
        assert_eq!(
            waiting.wait_first_attempt().await,
            FirstAttemptCompletion::Cancelled
        );
        assert_eq!(
            waiting.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_retry_failure_then_success_preserves_first_result() {
        let (store, stream, directory) = store_stream("retry-success");
        let attempts = Arc::new(AtomicUsize::new(0));
        let callback_attempts = attempts.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            if callback_attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                Err(io::Error::other("first attempt fails"))
            } else {
                Ok(LocalCleanupOutcome {
                    reclaimed_local_bytes: 9,
                })
            }
        });
        let executor = RetirementExecutor::new(cleanup, retry_config(2, Duration::ZERO)).unwrap();
        let scheduled_ticket = ticket(executor.admit(
            stream,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert_eq!(
            scheduled_ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        assert_eq!(
            scheduled_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded {
                reclaimed_local_bytes: 9
            }
        );
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_retry_permanent_failure_cools_down_and_releases_memory() {
        let (store, stream, directory) = store_stream("retry-permanent");
        let attempts = Arc::new(AtomicUsize::new(0));
        let callback_attempts = attempts.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            callback_attempts.fetch_add(1, Ordering::AcqRel);
            Err(io::Error::other("permanent"))
        });
        let executor = RetirementExecutor::new(cleanup, retry_config(2, Duration::ZERO)).unwrap();
        let scheduled_ticket = ticket(executor.admit(
            stream.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert_eq!(
            scheduled_ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        assert_eq!(
            scheduled_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Failed
        );
        assert_eq!(
            attempts.load(Ordering::Acquire),
            usize::from(MAX_CLEANUP_ATTEMPTS)
        );
        assert_eq!(executor.pending_and_jobs(), (0, 0, 0));
        assert_eq!(executor.scheduled_retry_count(), 0);
        assert!(matches!(
            executor.admit(
                stream,
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry
            ),
            RetirementAdmissionResult::Rejected(RetirementAdmission::CoolingDown)
        ));
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_retry_shutdown_and_drop_cancel_scheduled_work() {
        let (store, first, directory) = store_stream("retry-cancel");
        let attempts = Arc::new(AtomicUsize::new(0));
        let callback_attempts = attempts.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            callback_attempts.fetch_add(1, Ordering::AcqRel);
            Err(io::Error::other("retry later"))
        });
        let executor =
            RetirementExecutor::new(cleanup.clone(), retry_config(2, Duration::from_secs(60)))
                .unwrap();
        let scheduled_ticket = ticket(executor.admit(
            first,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert_eq!(
            scheduled_ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        executor.shutdown().await;
        assert_eq!(
            scheduled_ticket.wait_logical().await,
            LogicalCompletion::Cancelled
        );
        assert_eq!(
            scheduled_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        assert_eq!(attempts.load(Ordering::Acquire), 1);

        let dropped =
            RetirementExecutor::new(cleanup, retry_config(2, Duration::from_secs(60))).unwrap();
        let dropped_ticket = ticket(dropped.admit(
            stream(&store, "dropped"),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert_eq!(
            dropped_ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        drop(dropped);
        assert_eq!(
            dropped_ticket.wait_logical().await,
            LogicalCompletion::Cancelled
        );
        assert_eq!(
            dropped_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_retry_success_on_first_attempt_does_not_schedule() {
        let (store, stream, directory) = store_stream("retry-first-success");
        let attempts = Arc::new(AtomicUsize::new(0));
        let callback_attempts = attempts.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            callback_attempts.fetch_add(1, Ordering::AcqRel);
            Ok(LocalCleanupOutcome::default())
        });
        let executor = RetirementExecutor::new(cleanup, retry_config(2, Duration::ZERO)).unwrap();
        let ticket = ticket(executor.admit(
            stream,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert!(matches!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        assert_eq!(attempts.load(Ordering::Acquire), 1);
        assert_eq!(executor.scheduled_retry_count(), 0);
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn retirement_queue_coordinator_retry_backoff_is_capped_and_overflow_safe() {
        let base = Duration::from_secs(1);
        assert_eq!(retry_backoff(1, base), Duration::from_secs(1));
        assert_eq!(retry_backoff(2, base), Duration::from_secs(2));
        assert_eq!(retry_backoff(3, base), Duration::from_secs(4));
        assert_eq!(retry_backoff(7, base), Duration::from_secs(60));
        assert_eq!(
            retry_backoff(u8::MAX, Duration::MAX),
            Duration::from_secs(60)
        );
    }
}
