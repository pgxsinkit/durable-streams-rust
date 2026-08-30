//! Bounded retirement coordinator with one supervised retry timer.
//!
//! This slice owns admission and scheduling only. Logical retirement is still
//! completed by the later handler-ordering slice.

// TODO(retirement-005): handler retirement wiring makes this coordinator live.
#![allow(dead_code)]

use std::cmp::{Ordering as CmpOrdering, Reverse};
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{mpsc, Notify};

use crate::store::{LocalCleanupDisposition, LocalCleanupMode, StreamState};

use super::{
    retry_backoff, CleanupCallback, FirstAttemptCompletion, LogicalCompletion,
    PhysicalAttemptResult, PhysicalExecutor, PhysicalSubmitError, RetirementAdmission,
    RetirementConfig, RetirementPriority, RetirementReservation, RetirementSnapshot,
    RetirementTicket, TerminalCleanupCompletion, MAX_CLEANUP_ATTEMPTS,
};

/// The result of an admission attempt. Duplicate admissions return the exact
/// same level-triggered ticket as the original caller.
pub(crate) enum RetirementAdmissionResult {
    Admitted(RetirementTicket),
    Existing(RetirementTicket),
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
    logical_released: bool,
    active_attempt: Option<u8>,
    retry_scheduled: bool,
    first_attempt_completed: bool,
    admitted_sequence: u64,
}

/// An intrusive, insertion-ordered index over the bounded job table.  A
/// snapshot needs only the oldest node, while admission and removal relink at
/// most two neighbours; none of those paths walks retained jobs.
struct AdmissionNode {
    admitted_at: Instant,
    previous: Option<u64>,
    next: Option<u64>,
}

/// O(1) identity-safe expiry-fence index. Weak identity keeps telemetry from
/// extending stream lifetime after a terminal cooldown or replacement.
struct ExpiryFenceNode {
    stream: Weak<StreamState>,
    fenced_at: Instant,
    previous: Option<u64>,
    next: Option<u64>,
    terminal_failure: bool,
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
    next_admission_sequence: u64,
    admitted: HashMap<u64, AdmissionNode>,
    oldest_admission: Option<u64>,
    newest_admission: Option<u64>,
    expiry_jobs: u64,
    expiry_fences: HashMap<u64, ExpiryFenceNode>,
    oldest_expiry_fence: Option<u64>,
    newest_expiry_fence: Option<u64>,
    expiry_terminal_cleanup_failed_current: u64,
    cumulative_retry_attempts: u64,
    terminal_cleanup_failed_current: u64,
    terminal_successes: u64,
    terminal_failures: u64,
    terminal_cancellations: u64,
    first_attempt_successes: u64,
    first_attempt_failures: u64,
    first_attempt_cancellations: u64,
    reclaimed_local_bytes: u64,
    latest_cleanup_wall_time: Option<SystemTime>,
    last_successful_cleanup_wall_time: Option<SystemTime>,
    latest_cleanup_duration: Option<Duration>,
    last_successful_cleanup_duration: Option<Duration>,
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
    duration: Duration,
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

/// Lifetime lease stored in the exact StreamState retirement state. It owns no
/// stream or executor strongly; on stream disposal it removes only the matching
/// weak identity from the O(1) expiry-fence index.
pub(crate) struct ExpiryFenceLease {
    inner: Weak<Inner>,
    id: u64,
    stream: Weak<StreamState>,
}

impl Drop for ExpiryFenceLease {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let removed = {
            let mut state = lock_recover(&inner.state);
            if state.closed {
                false
            } else if state
                .expiry_fences
                .get(&self.id)
                .is_some_and(|node| Weak::ptr_eq(&node.stream, &self.stream))
            {
                remove_expiry_fence_by_id(&mut state, self.id);
                true
            } else {
                false
            }
        };
        if removed {
            emit_expiry_telemetry(&inner);
        }
    }
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
        let executor = Self { inner };
        executor.emit_expiry_telemetry();
        Ok(executor)
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

        let (ticket, cleared_terminal_failure) = {
            let mut retirement = stream.retirement_state();
            let had_terminal_failure = retirement.has_terminal_failure();
            match retirement.reserve(Instant::now()) {
                RetirementReservation::Existing(ticket) => {
                    return RetirementAdmissionResult::Existing(ticket);
                }
                RetirementReservation::CoolingDown => {
                    return RetirementAdmissionResult::Rejected(RetirementAdmission::CoolingDown);
                }
                RetirementReservation::New(ticket) => (ticket, had_terminal_failure),
            }
        };

        if cleared_terminal_failure {
            state.terminal_cleanup_failed_current =
                state.terminal_cleanup_failed_current.saturating_sub(1);
            clear_expiry_fence_failure(&mut state, &stream);
        }

        if state.jobs.contains_key(&stream.id) {
            // A path replacement must never overwrite the retained job just
            // because its test/recovery identity reused the numeric ID.
            stream.retirement_state().finish(&ticket);
            drop(state);
            self.emit_expiry_telemetry();
            return RetirementAdmissionResult::Rejected(RetirementAdmission::IdentityConflict);
        }

        if state.jobs.len() >= self.inner.config.queue_capacity {
            stream.retirement_state().finish(&ticket);
            drop(state);
            self.emit_expiry_telemetry();
            return RetirementAdmissionResult::Rejected(RetirementAdmission::QueueFull);
        }

        let job = Arc::new(Job {
            stream,
            ticket: ticket.clone(),
            priority,
            mode,
        });
        state.next_admission_sequence = state.next_admission_sequence.wrapping_add(1);
        let admitted_sequence = state.next_admission_sequence;
        let previous = state.newest_admission;
        state.admitted.insert(
            admitted_sequence,
            AdmissionNode {
                admitted_at: Instant::now(),
                previous,
                next: None,
            },
        );
        if let Some(previous) = previous {
            state
                .admitted
                .get_mut(&previous)
                .expect("newest admission remains retained")
                .next = Some(admitted_sequence);
        } else {
            state.oldest_admission = Some(admitted_sequence);
        }
        state.newest_admission = Some(admitted_sequence);
        state.jobs.insert(
            job.id(),
            JobRecord {
                job: job.clone(),
                logical_released: false,
                active_attempt: None,
                retry_scheduled: false,
                first_attempt_completed: false,
                admitted_sequence,
            },
        );
        if mode == LocalCleanupMode::Expiry {
            state.expiry_jobs = state.expiry_jobs.saturating_add(1);
        }
        drop(state);
        self.emit_expiry_telemetry();
        RetirementAdmissionResult::Admitted(ticket)
    }

    /// Releases one exact, pre-logical admission after the Store has completed
    /// its fencing and path-reuse linearization. Only this transition exposes
    /// the job to physical scheduling.
    pub(crate) fn release_logical(
        &self,
        stream: &Arc<StreamState>,
        ticket: &RetirementTicket,
    ) -> bool {
        {
            let mut state = lock_recover(&self.inner.state);
            let Some(record) = state.jobs.get_mut(&stream.id) else {
                return false;
            };
            if record.logical_released
                || !Arc::ptr_eq(&record.job.stream, stream)
                || !record.job.ticket.same_identity(ticket)
            {
                return false;
            }
            record.logical_released = true;
            let job = record.job.clone();
            // Publish before exposing the job to the coordinator. The
            // coordinator cannot observe the pending entry until this state
            // lock is released, so physical cleanup cannot win the logical
            // race.
            job.ticket.complete_logical(LogicalCompletion::Completed);
            match job.priority {
                RetirementPriority::Interactive => state.interactive_pending.push_back(job),
                RetirementPriority::Proactive => state.proactive_pending.push_back(job),
            }
        }
        self.inner.notify.notify_one();
        true
    }

    /// Rolls back a Store-side linearization failure before logical release.
    /// Once release succeeds, only normal completion/shutdown owns the job.
    pub(crate) fn cancel_prelogical(
        &self,
        stream: &Arc<StreamState>,
        ticket: &RetirementTicket,
    ) -> bool {
        let mut state = lock_recover(&self.inner.state);
        let job = {
            let Some(record) = state.jobs.get(&stream.id) else {
                return false;
            };
            if record.logical_released
                || !Arc::ptr_eq(&record.job.stream, stream)
                || !record.job.ticket.same_identity(ticket)
            {
                return false;
            }
            record.job.clone()
        };
        // Keep coordinator state and RetirementState synchronized. In
        // particular, a new admission cannot see the old reservation after
        // the record is gone and spuriously become an Existing caller.
        job.ticket.complete_logical(LogicalCompletion::Cancelled);
        job.ticket
            .complete_first_attempt(FirstAttemptCompletion::Cancelled);
        job.ticket
            .complete_terminal(TerminalCleanupCompletion::Cancelled);
        job.stream.retirement_state().finish(&job.ticket);
        remove_job(&mut state, stream.id);
        state.terminal_cancellations = state.terminal_cancellations.saturating_add(1);
        state.first_attempt_cancellations = state.first_attempt_cancellations.saturating_add(1);
        drop(state);
        self.emit_expiry_telemetry();
        true
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
            let jobs = std::mem::take(&mut state.jobs);
            state.admitted.clear();
            state.oldest_admission = None;
            state.newest_admission = None;
            state.expiry_jobs = 0;
            state.expiry_fences.clear();
            state.oldest_expiry_fence = None;
            state.newest_expiry_fence = None;
            state.expiry_terminal_cleanup_failed_current = 0;
            let first_cancellations = jobs
                .values()
                .filter(|record| !record.first_attempt_completed)
                .count();
            state.terminal_cancellations = state
                .terminal_cancellations
                .saturating_add(u64::try_from(jobs.len()).unwrap_or(u64::MAX));
            state.first_attempt_cancellations = state
                .first_attempt_cancellations
                .saturating_add(u64::try_from(first_cancellations).unwrap_or(u64::MAX));
            jobs
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
        self.emit_expiry_telemetry();
        self.inner.notify.notify_waiters();
    }

    #[cfg(test)]
    fn active_counts(&self) -> (usize, usize) {
        let state = lock_recover(&self.inner.state);
        (state.active_interactive, state.active_proactive)
    }

    #[cfg(test)]
    pub(crate) fn pending_and_jobs(&self) -> (usize, usize, usize) {
        let state = lock_recover(&self.inner.state);
        (
            state.jobs.len(),
            state.interactive_pending.len(),
            state.proactive_pending.len(),
        )
    }

    #[cfg(test)]
    pub(crate) fn expiry_telemetry_state_for_test(&self) -> (u64, u64, Option<Duration>) {
        let state = lock_recover(&self.inner.state);
        let oldest_age = state.oldest_expiry_fence.and_then(|id| {
            state
                .expiry_fences
                .get(&id)
                .map(|node| Instant::now().saturating_duration_since(node.fenced_at))
        });
        (
            state.expiry_jobs,
            state.expiry_terminal_cleanup_failed_current,
            oldest_age,
        )
    }

    #[cfg(test)]
    fn scheduled_retry_count(&self) -> usize {
        lock_recover(&self.inner.state).retries.len()
    }

    #[cfg(test)]
    pub(crate) fn worker_count(&self) -> usize {
        self.inner.physical.worker_count()
    }

    pub(crate) fn snapshot(&self) -> RetirementSnapshot {
        let state = lock_recover(&self.inner.state);
        let physical = self.inner.physical.snapshot();
        let oldest_admitted_age = state.oldest_admission.and_then(|sequence| {
            state
                .admitted
                .get(&sequence)
                .map(|node| Instant::now().saturating_duration_since(node.admitted_at))
        });
        RetirementSnapshot {
            queue_capacity: self.inner.config.queue_capacity,
            total_jobs: state.jobs.len(),
            interactive_pending: state.interactive_pending.len(),
            proactive_pending: state.proactive_pending.len(),
            active_interactive: state.active_interactive,
            active_proactive: state.active_proactive,
            coordinator_capacity: self.inner.config.coordinator_capacity,
            proactive_coordinator_capacity: self.inner.config.proactive_coordinator_capacity,
            interactive_physical_capacity: self.inner.config.interactive_physical_capacity,
            proactive_physical_capacity: self.inner.config.proactive_physical_capacity,
            physical_interactive_queued: physical.interactive_queued,
            physical_proactive_queued: physical.proactive_queued,
            physical_interactive_active: physical.interactive_active,
            physical_proactive_active: physical.proactive_active,
            cleanup_workers_total: physical.workers_total,
            cleanup_workers_live: physical.workers_live,
            retry_heap_count: state.retries.len(),
            cumulative_retry_attempts: state.cumulative_retry_attempts,
            terminal_cleanup_failed_current: state.terminal_cleanup_failed_current,
            terminal_successes: state.terminal_successes,
            terminal_failures: state.terminal_failures,
            terminal_cancellations: state.terminal_cancellations,
            first_attempt_successes: state.first_attempt_successes,
            first_attempt_failures: state.first_attempt_failures,
            first_attempt_cancellations: state.first_attempt_cancellations,
            reclaimed_local_bytes: state.reclaimed_local_bytes,
            latest_cleanup_wall_time: state.latest_cleanup_wall_time,
            last_successful_cleanup_wall_time: state.last_successful_cleanup_wall_time,
            latest_cleanup_duration: state.latest_cleanup_duration,
            last_successful_cleanup_duration: state.last_successful_cleanup_duration,
            oldest_admitted_age,
            closed: state.closed || physical.closed,
        }
    }

    pub(crate) fn emit_expiry_telemetry(&self) {
        emit_expiry_telemetry(&self.inner);
    }

    /// Store calls this only after it has applied the exact expiry fence while
    /// holding the appender lock. Cancellation and cooldown deliberately leave
    /// the marker intact until an exact hard cleanup or shutdown removes it.
    pub(crate) fn mark_expiry_fence(&self, stream: &Arc<StreamState>) {
        let inserted = {
            let mut state = lock_recover(&self.inner.state);
            if state.closed {
                return;
            }
            mark_expiry_fence(&mut state, stream)
        };
        if inserted {
            let previous_lease = {
                let mut retirement_state = stream.retirement_state();
                retirement_state.install_expiry_fence_lease(ExpiryFenceLease {
                    inner: Arc::downgrade(&self.inner),
                    id: stream.id,
                    stream: Arc::downgrade(stream),
                })
            };
            drop(previous_lease);
        }
        self.emit_expiry_telemetry();
    }
}

fn remove_job(state: &mut CoordinatorState, id: u64) -> Option<JobRecord> {
    let record = state.jobs.remove(&id)?;
    if record.job.mode == LocalCleanupMode::Expiry {
        state.expiry_jobs = state.expiry_jobs.saturating_sub(1);
    }
    let node = state
        .admitted
        .remove(&record.admitted_sequence)
        .expect("retained job has an admission node");
    if let Some(previous) = node.previous {
        state
            .admitted
            .get_mut(&previous)
            .expect("previous admission remains retained")
            .next = node.next;
    } else {
        state.oldest_admission = node.next;
    }
    if let Some(next) = node.next {
        state
            .admitted
            .get_mut(&next)
            .expect("next admission remains retained")
            .previous = node.previous;
    } else {
        state.newest_admission = node.previous;
    }
    Some(record)
}

fn mark_expiry_fence(state: &mut CoordinatorState, stream: &Arc<StreamState>) -> bool {
    let identity = Arc::downgrade(stream);
    if state
        .expiry_fences
        .get(&stream.id)
        .is_some_and(|node| Weak::ptr_eq(&node.stream, &identity))
    {
        return false;
    }
    remove_expiry_fence_by_id(state, stream.id);
    let previous = state.newest_expiry_fence;
    state.expiry_fences.insert(
        stream.id,
        ExpiryFenceNode {
            stream: identity,
            fenced_at: Instant::now(),
            previous,
            next: None,
            terminal_failure: false,
        },
    );
    if let Some(previous) = previous {
        state
            .expiry_fences
            .get_mut(&previous)
            .expect("newest expiry fence remains retained")
            .next = Some(stream.id);
    } else {
        state.oldest_expiry_fence = Some(stream.id);
    }
    state.newest_expiry_fence = Some(stream.id);
    true
}

fn remove_expiry_fence(state: &mut CoordinatorState, stream: &Arc<StreamState>) {
    let identity = Arc::downgrade(stream);
    if state
        .expiry_fences
        .get(&stream.id)
        .is_some_and(|node| Weak::ptr_eq(&node.stream, &identity))
    {
        remove_expiry_fence_by_id(state, stream.id);
    }
}

fn remove_expiry_fence_by_id(state: &mut CoordinatorState, id: u64) {
    let Some(node) = state.expiry_fences.remove(&id) else {
        return;
    };
    if node.terminal_failure {
        state.expiry_terminal_cleanup_failed_current = state
            .expiry_terminal_cleanup_failed_current
            .saturating_sub(1);
    }
    if let Some(previous) = node.previous {
        state
            .expiry_fences
            .get_mut(&previous)
            .expect("previous expiry fence remains retained")
            .next = node.next;
    } else {
        state.oldest_expiry_fence = node.next;
    }
    if let Some(next) = node.next {
        state
            .expiry_fences
            .get_mut(&next)
            .expect("next expiry fence remains retained")
            .previous = node.previous;
    } else {
        state.newest_expiry_fence = node.previous;
    }
}

fn clear_expiry_fence_failure(state: &mut CoordinatorState, stream: &Arc<StreamState>) {
    let identity = Arc::downgrade(stream);
    if let Some(node) = state.expiry_fences.get_mut(&stream.id) {
        if Weak::ptr_eq(&node.stream, &identity) && node.terminal_failure {
            node.terminal_failure = false;
            state.expiry_terminal_cleanup_failed_current = state
                .expiry_terminal_cleanup_failed_current
                .saturating_sub(1);
        }
    }
}

fn mark_expiry_fence_failure(
    state: &mut CoordinatorState,
    mode: LocalCleanupMode,
    stream: &Arc<StreamState>,
) {
    if mode != LocalCleanupMode::Expiry {
        return;
    }
    let identity = Arc::downgrade(stream);
    if let Some(node) = state.expiry_fences.get_mut(&stream.id) {
        if Weak::ptr_eq(&node.stream, &identity) && !node.terminal_failure {
            node.terminal_failure = true;
            state.expiry_terminal_cleanup_failed_current = state
                .expiry_terminal_cleanup_failed_current
                .saturating_add(1);
        }
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
            #[cfg(feature = "telemetry")]
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => finish_attempt(&inner, event),
                    None => return,
                },
                _ = &mut notified => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(due)) => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => emit_expiry_telemetry(&inner),
            }
            #[cfg(not(feature = "telemetry"))]
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => finish_attempt(&inner, event),
                    None => return,
                },
                _ = &mut notified => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(due)) => {},
            }
        } else {
            #[cfg(feature = "telemetry")]
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => finish_attempt(&inner, event),
                    None => return,
                },
                _ = &mut notified => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => emit_expiry_telemetry(&inner),
            }
            #[cfg(not(feature = "telemetry"))]
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
            let valid = state.jobs.get(&job.id()).is_some_and(|record| {
                record.logical_released
                    && record.active_attempt.is_none()
                    && !record.retry_scheduled
                    && Arc::ptr_eq(&record.job.stream, &job.stream)
                    && record.job.ticket.same_identity(&job.ticket)
            });
            if !valid {
                // An early entry is still retained in `jobs`; its eventual
                // release enqueues a fresh, valid entry. A stale duplicate
                // likewise has an active/retrying/replaced owner (or was
                // already settled). Dropping only this queue copy keeps it
                // from blocking later valid work without stranding a ticket.
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
                    if attempt_number > 1 {
                        state.cumulative_retry_attempts =
                            state.cumulative_retry_attempts.saturating_add(1);
                    }
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
                    let completion = attempt.wait_completion().await;
                    let _ = events
                        .send(WorkerEvent {
                            id: job.id(),
                            attempt: attempt_number,
                            result: completion.result,
                            duration: completion.duration,
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
    remove_job(state, job.id());
    if cancelled {
        state.terminal_cancellations = state.terminal_cancellations.saturating_add(1);
        state.first_attempt_cancellations = state.first_attempt_cancellations.saturating_add(1);
        job.ticket.complete_logical(LogicalCompletion::Cancelled);
        job.ticket
            .complete_first_attempt(FirstAttemptCompletion::Cancelled);
        job.ticket
            .complete_terminal(TerminalCleanupCompletion::Cancelled);
    } else {
        state.terminal_failures = state.terminal_failures.saturating_add(1);
        state.first_attempt_failures = state.first_attempt_failures.saturating_add(1);
        job.ticket
            .complete_first_attempt(FirstAttemptCompletion::Failed);
        job.ticket
            .complete_terminal(TerminalCleanupCompletion::Failed);
    }
    job.stream.retirement_state().finish(&job.ticket);
}

fn finish_attempt(inner: &Inner, event: WorkerEvent) {
    let (outcome, cleanup_telemetry) = {
        let mut state = lock_recover(&inner.state);
        let job = match state.jobs.get_mut(&event.id) {
            Some(record) if record.active_attempt == Some(event.attempt) => {
                record.active_attempt = None;
                record.job.clone()
            }
            _ => return,
        };
        // No accounting is touched until the retained job and exact attempt
        // have both matched: worker completions may arrive after cancel_all.
        let wall_now = SystemTime::now();
        state.latest_cleanup_wall_time = Some(wall_now);
        state.latest_cleanup_duration = Some(event.duration);
        if event.attempt == 1 {
            if let Some(record) = state.jobs.get_mut(&event.id) {
                record.first_attempt_completed = true;
            }
        }
        match job.priority {
            RetirementPriority::Interactive => {
                state.active_interactive = state.active_interactive.saturating_sub(1)
            }
            RetirementPriority::Proactive => {
                state.active_proactive = state.active_proactive.saturating_sub(1)
            }
        }
        let cleanup_telemetry = expiry_cleanup_telemetry(job.mode, event.result, event.duration);
        let outcome = match event.result {
            PhysicalAttemptResult::Succeeded {
                reclaimed_local_bytes,
                disposition,
            } => {
                remove_job(&mut state, event.id);
                state.terminal_successes = state.terminal_successes.saturating_add(1);
                state.reclaimed_local_bytes = state
                    .reclaimed_local_bytes
                    .saturating_add(reclaimed_local_bytes);
                state.last_successful_cleanup_wall_time = Some(wall_now);
                state.last_successful_cleanup_duration = Some(event.duration);
                if disposition == LocalCleanupDisposition::HardReaped {
                    remove_expiry_fence(&mut state, &job.stream);
                }
                AttemptOutcome::Succeeded(job, reclaimed_local_bytes, disposition)
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
                remove_job(&mut state, event.id);
                state.terminal_failures = state.terminal_failures.saturating_add(1);
                state.terminal_cleanup_failed_current =
                    state.terminal_cleanup_failed_current.saturating_add(1);
                mark_expiry_fence_failure(&mut state, job.mode, &job.stream);
                AttemptOutcome::Failed(job)
            }
            PhysicalAttemptResult::Cancelled => {
                remove_job(&mut state, event.id);
                state.terminal_cancellations = state.terminal_cancellations.saturating_add(1);
                AttemptOutcome::Cancelled(job)
            }
        };
        if event.attempt == 1 {
            match &outcome {
                AttemptOutcome::Succeeded(..) => {
                    state.first_attempt_successes = state.first_attempt_successes.saturating_add(1)
                }
                AttemptOutcome::Retry(..) | AttemptOutcome::Failed(..) => {
                    state.first_attempt_failures = state.first_attempt_failures.saturating_add(1)
                }
                AttemptOutcome::Cancelled(..) => {
                    state.first_attempt_cancellations =
                        state.first_attempt_cancellations.saturating_add(1)
                }
            }
        }
        (outcome, cleanup_telemetry)
    };
    if let Some(cleanup_telemetry) = cleanup_telemetry {
        crate::telemetry::record_expiry_cleanup_attempt(cleanup_telemetry);
    }
    if event.attempt == 1 {
        match &outcome {
            AttemptOutcome::Succeeded(job, reclaimed_local_bytes, _) => {
                job.ticket
                    .complete_first_attempt(FirstAttemptCompletion::Succeeded {
                        reclaimed_local_bytes: *reclaimed_local_bytes,
                    });
            }
            AttemptOutcome::Retry(job) | AttemptOutcome::Failed(job) => {
                job.ticket
                    .complete_first_attempt(FirstAttemptCompletion::Failed);
            }
            AttemptOutcome::Cancelled(job) => {
                job.ticket
                    .complete_first_attempt(FirstAttemptCompletion::Cancelled);
            }
        }
    }
    match outcome {
        AttemptOutcome::Succeeded(job, reclaimed_local_bytes, _) => {
            job.stream.retirement_state().finish(&job.ticket);
            job.ticket
                .complete_terminal(TerminalCleanupCompletion::Succeeded {
                    reclaimed_local_bytes,
                });
        }
        AttemptOutcome::Retry(job) => {
            if job.mode == LocalCleanupMode::Expiry {
                crate::telemetry::record_expiry_cleanup_retry();
            }
        }
        AttemptOutcome::Failed(job) => {
            if job.mode == LocalCleanupMode::Expiry {
                crate::telemetry::record_expiry_outcome(crate::telemetry::ExpiryOutcomeDelta {
                    outcome: crate::telemetry::ExpiryOutcome::Failed,
                    count: 1,
                });
            }
            job.stream.retirement_state().fail_terminal(
                &job.ticket,
                Instant::now(),
                SystemTime::now(),
                inner.config.cooldown,
            );
            job.ticket
                .complete_terminal(TerminalCleanupCompletion::Failed);
        }
        AttemptOutcome::Cancelled(job) => {
            job.stream.retirement_state().finish(&job.ticket);
            job.ticket
                .complete_terminal(TerminalCleanupCompletion::Cancelled);
        }
    }
    emit_expiry_telemetry(inner);
    inner.notify.notify_one();
}

/// Map only a matched physical Expiry attempt into the bounded cleanup metric
/// event. Explicit deletion and cascade cleanup share the executor but are not
/// expiry telemetry, so they return no event at all.
fn expiry_cleanup_telemetry(
    mode: LocalCleanupMode,
    result: PhysicalAttemptResult,
    duration: Duration,
) -> Option<crate::telemetry::ExpiryCleanupTelemetry> {
    if mode != LocalCleanupMode::Expiry {
        return None;
    }
    Some(crate::telemetry::ExpiryCleanupTelemetry {
        duration_seconds: duration.as_secs_f64(),
        disposition: match result {
            PhysicalAttemptResult::Succeeded {
                reclaimed_local_bytes,
                disposition: LocalCleanupDisposition::HardReaped,
            } => Some(crate::telemetry::ExpiryCleanupDisposition::Reaped(
                reclaimed_local_bytes,
            )),
            PhysicalAttemptResult::Succeeded {
                disposition: LocalCleanupDisposition::DurableSoftDeleted,
                ..
            } => Some(crate::telemetry::ExpiryCleanupDisposition::SoftDeleted),
            PhysicalAttemptResult::Failed
            | PhysicalAttemptResult::Panicked
            | PhysicalAttemptResult::Cancelled => None,
        },
    })
}

enum AttemptOutcome {
    Succeeded(Arc<Job>, u64, LocalCleanupDisposition),
    Retry(Arc<Job>),
    Failed(Arc<Job>),
    Cancelled(Arc<Job>),
}

fn lock_recover<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Capture only bounded coordinator scalars, then record them after releasing
/// the coordinator lock. The scanner refreshes this same O(1) projection on
/// pages, so an idle retained fence's age does not stay permanently stale.
fn emit_expiry_telemetry(inner: &Inner) {
    #[cfg(not(feature = "telemetry"))]
    {
        let _ = inner;
    }
    #[cfg(feature = "telemetry")]
    {
        let snapshot = {
            let state = lock_recover(&inner.state);
            let oldest_fence_age_seconds = state.oldest_expiry_fence.and_then(|id| {
                state.expiry_fences.get(&id).map(|node| {
                    Instant::now()
                        .saturating_duration_since(node.fenced_at)
                        .as_secs_f64()
                })
            });
            crate::telemetry::ExpiryRetirementTelemetry {
                queue_depth: state.expiry_jobs,
                cleanup_failed: state.expiry_terminal_cleanup_failed_current,
                oldest_fence_age_seconds,
            }
        };
        crate::telemetry::record_expiry_retirement(snapshot);
    }
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
            RetirementAdmissionResult::Admitted(ticket)
            | RetirementAdmissionResult::Existing(ticket) => ticket,
            RetirementAdmissionResult::Rejected(reason) => {
                panic!("unexpected rejection: {reason:?}")
            }
        }
    }

    fn admit_released(
        executor: &RetirementExecutor,
        stream: Arc<StreamState>,
        priority: RetirementPriority,
        mode: LocalCleanupMode,
    ) -> RetirementTicket {
        match executor.admit(stream.clone(), priority, mode) {
            RetirementAdmissionResult::Admitted(ticket) => {
                assert!(executor.release_logical(&stream, &ticket));
                ticket
            }
            RetirementAdmissionResult::Existing(_) => panic!("stream was already admitted"),
            RetirementAdmissionResult::Rejected(reason) => {
                panic!("unexpected rejection: {reason:?}")
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_coordinator_deduplicates_ticket_and_retains_stream() {
        let (store, stream, directory) = store_stream("dedup");
        let executor = RetirementExecutor::new(callback(), config(2, 8, 0)).unwrap();
        let first = match executor.admit(
            stream.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Admitted(ticket) => ticket,
            _ => panic!("first admission must own the gate"),
        };
        let duplicate = match executor.admit(
            stream.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Existing(ticket) => ticket,
            _ => panic!("duplicate must share the owner ticket"),
        };
        assert!(first.same_identity(&duplicate));
        store.streams.remove("stream");
        let weak = Arc::downgrade(&stream);
        let release_stream = stream.clone();
        drop(stream);
        assert!(weak.upgrade().is_some());
        assert!(executor.release_logical(&release_stream, &first));
        assert_eq!(first.wait_logical().await, LogicalCompletion::Completed);
        assert!(matches!(
            first.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        executor.shutdown().await;
        drop(release_stream);
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
        let first_ticket = admit_released(
            &executor,
            first,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
        assert!(matches!(
            executor.admit(
                second.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry
            ),
            RetirementAdmissionResult::Rejected(RetirementAdmission::QueueFull)
        ));
        let saturated = executor.snapshot();
        assert_eq!(saturated.total_jobs, 1);
        assert_eq!(saturated.queue_capacity, 1);
        assert!(saturated.active_interactive <= 1);
        assert!(second.retirement_state().is_clean());
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(matches!(
            first_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        let retry = admit_released(
            &executor,
            second,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
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
            let _ = admit_released(
                &executor,
                item.clone(),
                RetirementPriority::Proactive,
                LocalCleanupMode::Expiry,
            );
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
        let interactive = admit_released(
            &executor,
            streams[3].clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
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
        let first_proactive = admit_released(
            &executor,
            first.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        );
        let second_proactive = admit_released(
            &executor,
            second.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        );
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
        let a = admit_released(
            &executor,
            third.clone(),
            RetirementPriority::Proactive,
            LocalCleanupMode::Expiry,
        );
        let b = admit_released(
            &executor,
            fourth.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
        let c = admit_released(
            &executor,
            fifth.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
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
        let failed = admit_released(
            &executor,
            failing,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
        assert_eq!(
            failed.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        assert_eq!(
            failed.wait_terminal().await,
            TerminalCleanupCompletion::Failed
        );
        assert_eq!(failed.wait_logical().await, LogicalCompletion::Completed);
        executor.shutdown().await;

        let pending = RetirementExecutor::new(callback(), config(2, 8, 0)).unwrap();
        let waiting_stream = stream(&store, "pending");
        let waiting = ticket(pending.admit(
            waiting_stream,
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
                    ..LocalCleanupOutcome::default()
                })
            }
        });
        let executor = RetirementExecutor::new(cleanup, retry_config(2, Duration::ZERO)).unwrap();
        let scheduled_ticket = admit_released(
            &executor,
            stream,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
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
        let snapshot = executor.snapshot();
        assert_eq!(snapshot.first_attempt_failures, 1);
        assert_eq!(snapshot.first_attempt_successes, 0);
        assert_eq!(snapshot.cumulative_retry_attempts, 1);
        assert_eq!(snapshot.terminal_successes, 1);
        assert_eq!(snapshot.terminal_failures, 0);
        assert_eq!(snapshot.first_attempt_cancellations, 0);
        assert_eq!(snapshot.reclaimed_local_bytes, 9);
        assert!(snapshot.latest_cleanup_wall_time.is_some());
        assert!(snapshot.latest_cleanup_duration.is_some());
        assert!(snapshot.last_successful_cleanup_duration.is_some());
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
        let scheduled_ticket = admit_released(
            &executor,
            stream.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
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
        let scheduled_ticket = admit_released(
            &executor,
            first,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
        assert_eq!(
            scheduled_ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        executor.shutdown().await;
        assert_eq!(
            scheduled_ticket.wait_logical().await,
            LogicalCompletion::Completed
        );
        assert_eq!(
            scheduled_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        assert_eq!(attempts.load(Ordering::Acquire), 1);

        let dropped =
            RetirementExecutor::new(cleanup, retry_config(2, Duration::from_secs(60))).unwrap();
        let dropped_stream = stream(&store, "dropped");
        let dropped_ticket = admit_released(
            &dropped,
            dropped_stream,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
        assert_eq!(
            dropped_ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        drop(dropped);
        assert_eq!(
            dropped_ticket.wait_logical().await,
            LogicalCompletion::Completed
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
        let ticket = admit_released(
            &executor,
            stream,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        );
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

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_logical_gate_owner_duplicate_and_one_time_release() {
        let (store, stream, directory) = store_stream("gate-owner");
        let (calls_tx, mut calls_rx) = tokio::sync::mpsc::unbounded_channel();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            let _ = calls_tx.send(());
            Ok(LocalCleanupOutcome::default())
        });
        let executor = RetirementExecutor::new(cleanup, config(2, 8, 0)).unwrap();
        let owner = match executor.admit(
            stream.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Admitted(ticket) => ticket,
            _ => panic!("first caller must own the logical gate"),
        };
        let duplicate = match executor.admit(
            stream.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Existing(ticket) => ticket,
            _ => panic!("duplicate must observe the retained ticket"),
        };
        assert!(owner.same_identity(&duplicate));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), calls_rx.recv())
                .await
                .is_err(),
            "cleanup must not start before logical release"
        );
        assert!(executor.release_logical(&stream, &owner));
        assert!(!executor.release_logical(&stream, &owner));
        assert_eq!(owner.wait_logical().await, LogicalCompletion::Completed);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), calls_rx.recv())
                .await
                .expect("released cleanup should start"),
            Some(())
        );
        assert!(matches!(
            owner.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), calls_rx.recv())
                .await
                .is_err(),
            "one release must submit exactly one cleanup"
        );
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_logical_gate_stale_identity_and_cancel_are_noops() {
        let (store, original, directory) = store_stream("gate-stale");
        let mut replacement = stream(&store, "replacement");
        store.streams.remove("replacement");
        Arc::get_mut(&mut replacement)
            .expect("test replacement must have no other owners")
            .id = original.id;
        let executor = RetirementExecutor::new(callback(), config(2, 8, 0)).unwrap();
        let first = match executor.admit(
            original.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Admitted(ticket) => ticket,
            _ => panic!("first caller must own the logical gate"),
        };
        assert!(!executor.release_logical(&replacement, &first));
        assert!(!executor.cancel_prelogical(&replacement, &first));
        assert!(matches!(
            executor.admit(
                replacement.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry
            ),
            RetirementAdmissionResult::Rejected(RetirementAdmission::IdentityConflict)
        ));
        assert!(replacement.retirement_state().is_clean());
        assert!(executor.cancel_prelogical(&original, &first));
        assert_eq!(first.wait_logical().await, LogicalCompletion::Cancelled);
        assert_eq!(
            first.wait_first_attempt().await,
            FirstAttemptCompletion::Cancelled
        );
        assert_eq!(
            first.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );

        let replacement_ticket = match executor.admit(
            original.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Admitted(ticket) => ticket,
            _ => panic!("cancelled admission must permit a new owner"),
        };
        assert!(!executor.release_logical(&original, &first));
        assert!(!executor.cancel_prelogical(&original, &first));
        assert!(executor.release_logical(&original, &replacement_ticket));
        assert!(!executor.cancel_prelogical(&original, &replacement_ticket));
        assert!(matches!(
            replacement_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_logical_gate_capacity_and_unreleased_shutdown_drop() {
        let (store, first, directory) = store_stream("gate-capacity");
        let second = stream(&store, "second");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let cleanup_callbacks = callbacks.clone();
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            cleanup_callbacks.fetch_add(1, Ordering::AcqRel);
            Ok(LocalCleanupOutcome::default())
        });
        let executor = RetirementExecutor::new(cleanup.clone(), config(1, 8, 0)).unwrap();
        let first_ticket = match executor.admit(
            first.clone(),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Admitted(ticket) => ticket,
            _ => panic!("first caller must own the logical gate"),
        };
        assert!(matches!(
            executor.admit(
                second.clone(),
                RetirementPriority::Interactive,
                LocalCleanupMode::Expiry
            ),
            RetirementAdmissionResult::Rejected(RetirementAdmission::QueueFull)
        ));
        assert!(executor.cancel_prelogical(&first, &first_ticket));
        let second_ticket = match executor.admit(
            second,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Admitted(ticket) => ticket,
            _ => panic!("rollback must free the bounded admission slot"),
        };
        executor.shutdown().await;
        assert_eq!(
            second_ticket.wait_logical().await,
            LogicalCompletion::Cancelled
        );
        assert_eq!(
            second_ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Cancelled
        );
        assert_eq!(
            second_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        assert_eq!(callbacks.load(Ordering::Acquire), 0);

        let dropped = RetirementExecutor::new(cleanup, config(1, 8, 0)).unwrap();
        let dropped_stream = stream(&store, "dropped");
        let dropped_ticket = match dropped.admit(
            dropped_stream,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ) {
            RetirementAdmissionResult::Admitted(ticket) => ticket,
            _ => panic!("drop test needs an unreleased owner"),
        };
        drop(dropped);
        assert_eq!(
            dropped_ticket.wait_logical().await,
            LogicalCompletion::Cancelled
        );
        assert_eq!(
            dropped_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        assert_eq!(callbacks.load(Ordering::Acquire), 0);
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

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_snapshot_tracks_logical_and_physical_lifecycle() {
        let (store, stream, directory) = store_stream("snapshot-lifecycle");
        let reclaimed = 37;
        let cleanup: CleanupCallback = Arc::new(move |_, _| {
            Ok(LocalCleanupOutcome {
                reclaimed_local_bytes: reclaimed,
                ..LocalCleanupOutcome::default()
            })
        });
        let executor = RetirementExecutor::new(cleanup, config(2, 8, 0)).unwrap();
        let empty = executor.snapshot();
        assert_eq!(empty.queue_capacity, 2);
        assert_eq!(empty.total_jobs, 0);
        assert_eq!(empty.cleanup_workers_total, 4);
        assert_eq!(empty.cleanup_workers_live, 4);

        let ticket = ticket(executor.admit(
            Arc::clone(&stream),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        let admitted = executor.snapshot();
        assert_eq!(admitted.total_jobs, 1);
        assert!(admitted.oldest_admitted_age.is_some());
        assert_eq!(admitted.interactive_pending, 0);
        assert!(executor.release_logical(&stream, &ticket));
        assert_eq!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded {
                reclaimed_local_bytes: reclaimed
            }
        );
        let completed = executor.snapshot();
        assert_eq!(completed.total_jobs, 0);
        assert_eq!(completed.terminal_successes, 1);
        assert_eq!(completed.first_attempt_successes, 1);
        assert_eq!(completed.reclaimed_local_bytes, reclaimed);
        assert!(completed.latest_cleanup_wall_time.is_some());
        assert!(completed.last_successful_cleanup_duration.is_some());
        assert_eq!(completed.oldest_admitted_age, None);
        executor.shutdown().await;
        assert!(executor.snapshot().closed);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_snapshot_counts_prelogical_cancellation_without_physical_reap() {
        let (store, stream, directory) = store_stream("snapshot-cancel");
        let executor = RetirementExecutor::new(
            Arc::new(|_, _| Ok(LocalCleanupOutcome::default())),
            config(1, 8, 0),
        )
        .unwrap();
        let ticket = ticket(executor.admit(
            Arc::clone(&stream),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert!(executor.cancel_prelogical(&stream, &ticket));
        let snapshot = executor.snapshot();
        assert_eq!(snapshot.total_jobs, 0);
        assert_eq!(snapshot.terminal_cancellations, 1);
        assert_eq!(snapshot.first_attempt_cancellations, 1);
        assert_eq!(snapshot.terminal_successes, 0);
        assert_eq!(snapshot.reclaimed_local_bytes, 0);
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expiry_telemetry_state_is_mode_scoped_and_fence_survives_prelogical_cancel() {
        let (store, expiry, directory) = store_stream("expiry-telemetry-state");
        let explicit = stream(&store, "explicit-telemetry-state");
        let executor = RetirementExecutor::new(
            Arc::new(|_, _| Ok(LocalCleanupOutcome::default())),
            config(3, 8, 0),
        )
        .unwrap();
        let expiry_ticket = ticket(executor.admit(
            Arc::clone(&expiry),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        executor.mark_expiry_fence(&expiry);
        let explicit_ticket = ticket(executor.admit(
            Arc::clone(&explicit),
            RetirementPriority::Interactive,
            LocalCleanupMode::ExplicitDelete,
        ));
        assert_eq!(executor.expiry_telemetry_state_for_test().0, 1);
        assert!(executor.expiry_telemetry_state_for_test().2.is_some());
        assert!(executor.cancel_prelogical(&expiry, &expiry_ticket));
        assert_eq!(executor.expiry_telemetry_state_for_test().0, 0);
        assert!(
            executor.expiry_telemetry_state_for_test().2.is_some(),
            "a WAL/prelogical cancellation keeps its expiry fence age"
        );
        assert!(executor.cancel_prelogical(&explicit, &explicit_ticket));
        executor.shutdown().await;
        assert_eq!(executor.expiry_telemetry_state_for_test(), (0, 0, None));
        // A Store appender can finish its exact fence recheck after shutdown;
        // that late mark must not repopulate the cleared telemetry projection.
        executor.mark_expiry_fence(&expiry);
        assert_eq!(executor.expiry_telemetry_state_for_test(), (0, 0, None));
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_fence_index_relinks_head_middle_and_tail_without_duplicate_identity() {
        let (store, first, directory) = store_stream("expiry-fence-relink");
        let middle = stream(&store, "expiry-fence-middle");
        let last = stream(&store, "expiry-fence-last");
        let mut state = CoordinatorState::default();

        assert!(mark_expiry_fence(&mut state, &first));
        assert!(mark_expiry_fence(&mut state, &middle));
        assert!(mark_expiry_fence(&mut state, &last));
        assert!(
            !mark_expiry_fence(&mut state, &middle),
            "the same exact identity has one fence node"
        );
        assert_eq!(state.oldest_expiry_fence, Some(first.id));
        assert_eq!(state.newest_expiry_fence, Some(last.id));

        remove_expiry_fence(&mut state, &middle);
        assert_eq!(
            state
                .expiry_fences
                .get(&first.id)
                .and_then(|node| node.next),
            Some(last.id)
        );
        assert_eq!(
            state
                .expiry_fences
                .get(&last.id)
                .and_then(|node| node.previous),
            Some(first.id)
        );

        remove_expiry_fence(&mut state, &first);
        assert_eq!(state.oldest_expiry_fence, Some(last.id));
        assert_eq!(
            state
                .expiry_fences
                .get(&last.id)
                .and_then(|node| node.previous),
            None
        );
        remove_expiry_fence(&mut state, &last);
        assert!(state.expiry_fences.is_empty());
        assert_eq!(state.oldest_expiry_fence, None);
        assert_eq!(state.newest_expiry_fence, None);

        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expiry_fence_lease_drop_removes_the_exact_middle_failure_node() {
        let (store, oldest, directory) = store_stream("expiry-fence-lease-drop");
        let middle = stream(&store, "expiry-fence-middle");
        let newest = stream(&store, "expiry-fence-newest");
        let executor = RetirementExecutor::new(callback(), config(3, 8, 0)).unwrap();
        executor.mark_expiry_fence(&oldest);
        executor.mark_expiry_fence(&middle);
        executor.mark_expiry_fence(&newest);
        {
            let mut state = lock_recover(&executor.inner.state);
            state
                .expiry_fences
                .get_mut(&middle.id)
                .expect("middle fence is retained")
                .terminal_failure = true;
            state.expiry_terminal_cleanup_failed_current = 1;
        }

        assert!(store.unregister_exact_for_test(&middle));
        let middle_id = middle.id;
        drop(middle);

        {
            let state = lock_recover(&executor.inner.state);
            assert_eq!(state.oldest_expiry_fence, Some(oldest.id));
            assert_eq!(state.newest_expiry_fence, Some(newest.id));
            assert!(!state.expiry_fences.contains_key(&middle_id));
            assert_eq!(state.expiry_terminal_cleanup_failed_current, 0);
            assert_eq!(
                state
                    .expiry_fences
                    .get(&oldest.id)
                    .and_then(|node| node.next),
                Some(newest.id)
            );
            assert_eq!(
                state
                    .expiry_fences
                    .get(&newest.id)
                    .and_then(|node| node.previous),
                Some(oldest.id)
            );
        }

        executor.shutdown().await;
        drop(newest);
        drop(oldest);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_cleanup_mapping_and_terminal_failure_state_are_mode_scoped() {
        let duration = Duration::from_millis(250);
        let hard_zero = PhysicalAttemptResult::Succeeded {
            reclaimed_local_bytes: 0,
            disposition: LocalCleanupDisposition::HardReaped,
        };
        let soft = PhysicalAttemptResult::Succeeded {
            reclaimed_local_bytes: 0,
            disposition: LocalCleanupDisposition::DurableSoftDeleted,
        };
        for mode in [
            LocalCleanupMode::ExplicitDelete,
            LocalCleanupMode::CascadeCollection,
        ] {
            assert_eq!(expiry_cleanup_telemetry(mode, hard_zero, duration), None);
            assert_eq!(expiry_cleanup_telemetry(mode, soft, duration), None);
            assert_eq!(
                expiry_cleanup_telemetry(mode, PhysicalAttemptResult::Failed, duration),
                None,
                "non-expiry retries/failures never emit expiry cleanup duration"
            );
        }
        assert_eq!(
            expiry_cleanup_telemetry(LocalCleanupMode::Expiry, hard_zero, duration),
            Some(crate::telemetry::ExpiryCleanupTelemetry {
                duration_seconds: duration.as_secs_f64(),
                disposition: Some(crate::telemetry::ExpiryCleanupDisposition::Reaped(0)),
            })
        );
        assert_eq!(
            expiry_cleanup_telemetry(LocalCleanupMode::Expiry, soft, duration),
            Some(crate::telemetry::ExpiryCleanupTelemetry {
                duration_seconds: duration.as_secs_f64(),
                disposition: Some(crate::telemetry::ExpiryCleanupDisposition::SoftDeleted),
            })
        );
        assert_eq!(
            expiry_cleanup_telemetry(
                LocalCleanupMode::Expiry,
                PhysicalAttemptResult::Failed,
                duration
            ),
            Some(crate::telemetry::ExpiryCleanupTelemetry {
                duration_seconds: duration.as_secs_f64(),
                disposition: None,
            })
        );

        let (store, expiry, directory) = store_stream("expiry-mode-failure");
        let mut state = CoordinatorState::default();
        assert!(mark_expiry_fence(&mut state, &expiry));
        mark_expiry_fence_failure(&mut state, LocalCleanupMode::ExplicitDelete, &expiry);
        mark_expiry_fence_failure(&mut state, LocalCleanupMode::CascadeCollection, &expiry);
        assert_eq!(state.expiry_terminal_cleanup_failed_current, 0);
        mark_expiry_fence_failure(&mut state, LocalCleanupMode::Expiry, &expiry);
        assert_eq!(state.expiry_terminal_cleanup_failed_current, 1);

        drop(expiry);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_snapshot_ignores_stale_worker_events_after_cancellation() {
        let (store, stream, directory) = store_stream("snapshot-stale-event");
        let executor = RetirementExecutor::new(
            Arc::new(|_, _| Ok(LocalCleanupOutcome::default())),
            config(1, 8, 0),
        )
        .unwrap();
        let ticket = ticket(executor.admit(
            Arc::clone(&stream),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        assert!(executor.cancel_prelogical(&stream, &ticket));
        let before = executor.snapshot();
        finish_attempt(
            &executor.inner,
            WorkerEvent {
                id: stream.id,
                attempt: 1,
                result: PhysicalAttemptResult::Succeeded {
                    reclaimed_local_bytes: 99,
                    disposition: LocalCleanupDisposition::HardReaped,
                },
                duration: Duration::from_secs(1),
            },
        );
        let after = executor.snapshot();
        assert_eq!(
            after.latest_cleanup_wall_time,
            before.latest_cleanup_wall_time
        );
        assert_eq!(
            after.latest_cleanup_duration,
            before.latest_cleanup_duration
        );
        assert_eq!(after.terminal_successes, before.terminal_successes);
        assert_eq!(after.reclaimed_local_bytes, before.reclaimed_local_bytes);
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_snapshot_ignores_stale_worker_events_after_shutdown() {
        let (store, stream, directory) = store_stream("snapshot-stale-shutdown");
        let executor = RetirementExecutor::new(
            Arc::new(|_, _| Ok(LocalCleanupOutcome::default())),
            config(1, 8, 0),
        )
        .unwrap();
        let _ticket = ticket(executor.admit(
            Arc::clone(&stream),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        executor.shutdown().await;
        let before = executor.snapshot();
        assert_eq!(before.terminal_cancellations, 1);
        assert_eq!(before.first_attempt_cancellations, 1);

        finish_attempt(
            &executor.inner,
            WorkerEvent {
                id: stream.id,
                attempt: 1,
                result: PhysicalAttemptResult::Succeeded {
                    reclaimed_local_bytes: 99,
                    disposition: LocalCleanupDisposition::HardReaped,
                },
                duration: Duration::from_secs(1),
            },
        );
        assert_eq!(executor.snapshot(), before);

        // Shutdown owns the cancellation transition; the Drop path's shared
        // cancel_all call and any stale worker completion are both no-ops.
        executor.cancel_all();
        assert_eq!(executor.snapshot(), before);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_shutdown_and_drop_count_cancellation_once() {
        let (store, stream, directory) = store_stream("snapshot-shutdown-drop-once");
        let executor = RetirementExecutor::new(callback(), config(1, 8, 0)).unwrap();
        let shutdown_ticket = ticket(executor.admit(
            Arc::clone(&stream),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        executor.shutdown().await;
        let after_shutdown = executor.snapshot();
        assert_eq!(after_shutdown.terminal_cancellations, 1);
        assert_eq!(after_shutdown.first_attempt_cancellations, 1);
        executor.cancel_all();
        assert_eq!(executor.snapshot(), after_shutdown);
        drop(executor);
        assert_eq!(
            shutdown_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );

        let dropped = RetirementExecutor::new(callback(), config(1, 8, 0)).unwrap();
        let dropped_ticket = ticket(dropped.admit(
            stream,
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        let dropped_inner = Arc::clone(&dropped.inner);
        drop(dropped);
        {
            let state = lock_recover(&dropped_inner.state);
            assert_eq!(state.terminal_cancellations, 1);
            assert_eq!(state.first_attempt_cancellations, 1);
        }
        assert_eq!(
            dropped_ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        drop(dropped_inner);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_snapshot_publishes_first_and_terminal_attempt_one_together() {
        let (store, stream, directory) = store_stream("snapshot-attempt-one-atomic");
        let executor = RetirementExecutor::new(callback(), config(1, 8, 0)).unwrap();
        let ticket = ticket(executor.admit(
            Arc::clone(&stream),
            RetirementPriority::Interactive,
            LocalCleanupMode::Expiry,
        ));
        {
            let mut state = lock_recover(&executor.inner.state);
            let record = state.jobs.get_mut(&stream.id).expect("admitted job");
            record.active_attempt = Some(1);
            state.active_interactive = 1;
        }

        // finish_attempt is the completion barrier: its snapshot must never
        // expose the terminal first attempt without its first-attempt count.
        finish_attempt(
            &executor.inner,
            WorkerEvent {
                id: stream.id,
                attempt: 1,
                result: PhysicalAttemptResult::Succeeded {
                    reclaimed_local_bytes: 7,
                    disposition: LocalCleanupDisposition::HardReaped,
                },
                duration: Duration::from_millis(3),
            },
        );
        let snapshot = executor.snapshot();
        assert_eq!(snapshot.terminal_successes, 1);
        assert_eq!(snapshot.first_attempt_successes, 1);
        assert_eq!(snapshot.active_interactive, 0);
        assert_eq!(snapshot.total_jobs, 0);
        assert_eq!(snapshot.reclaimed_local_bytes, 7);
        assert!(snapshot.latest_cleanup_wall_time.is_some());
        assert!(snapshot.last_successful_cleanup_wall_time.is_some());
        assert_eq!(
            ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Succeeded {
                reclaimed_local_bytes: 7
            }
        );
        assert_eq!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded {
                reclaimed_local_bytes: 7
            }
        );
        executor.shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }
}
