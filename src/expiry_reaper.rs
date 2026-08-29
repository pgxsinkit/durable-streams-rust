use crate::store::{
    ExpiryCandidate, ExpiryScanCursor, PrepareRetirement, RetirementDurability, RetirementOutcome,
    Store,
};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

pub const MAX_SCAN_RATE: usize = 1_000_000;
pub const MAX_DELETE_RATE: usize = 100_000;
pub const MAX_DELETE_CONCURRENCY: usize = 1_024;
/// Do not convert an ordinary small sample into a process-lifetime bulk pause.
pub const MIN_BULK_DUE_COUNT: usize = 64;
const RETIREMENT_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
/// Initial retirement plus five exponentially-backed-off retries. A sixth
/// failure quarantines the exact incarnation until process restart.
const MAX_RETIREMENT_ATTEMPTS: u32 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Observe,
    Delete,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    pub scan_rate: usize,
    pub delete_rate: usize,
    pub delete_concurrency: usize,
    pub startup_grace: Duration,
    pub bulk_fraction: f64,
    pub clock_jump: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Off,
            scan_rate: 10_000,
            delete_rate: 100,
            delete_concurrency: 4,
            startup_grace: Duration::from_secs(60),
            bulk_fraction: 0.25,
            clock_jump: Duration::from_secs(300),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseReason {
    Bulk,
}

pub struct DeleteGate {
    config: Config,
    started_at: Duration,
    observed_pass: bool,
    pass_checked: usize,
    pass_due: usize,
    pause: Option<PauseReason>,
}

impl DeleteGate {
    pub fn new(config: Config, started_at: Duration) -> Self {
        Self {
            config,
            started_at,
            observed_pass: false,
            pass_checked: 0,
            pass_due: 0,
            pause: None,
        }
    }

    pub fn observe_page(
        &mut self,
        now: Duration,
        checked: usize,
        due: usize,
        completed_pass: bool,
    ) -> bool {
        let had_observed_pass = self.observed_pass;
        self.pass_checked = self.pass_checked.saturating_add(checked);
        self.pass_due = self.pass_due.saturating_add(due);

        let bulk_exceeded = self.pass_due >= MIN_BULK_DUE_COUNT
            && self.pass_checked > 0
            && (self.pass_due as f64 / self.pass_checked as f64) > self.config.bulk_fraction;
        if bulk_exceeded {
            self.pause.get_or_insert(PauseReason::Bulk);
        }

        let grace_elapsed = now
            .checked_sub(self.started_at)
            .is_some_and(|elapsed| elapsed >= self.config.startup_grace);
        let may_delete = self.config.mode == Mode::Delete
            && had_observed_pass
            && grace_elapsed
            && self.pause.is_none();

        if completed_pass {
            self.observed_pass = true;
            self.pass_checked = 0;
            self.pass_due = 0;
        }
        may_delete
    }

    pub fn pause(&self) -> Option<PauseReason> {
        self.pause
    }
}

pub struct ClockGuard {
    threshold: Duration,
    previous: Option<(SystemTime, Duration)>,
    last_drift: Duration,
    paused: bool,
}

impl ClockGuard {
    pub fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            previous: None,
            last_drift: Duration::ZERO,
            paused: false,
        }
    }

    pub fn observe(&mut self, wall: SystemTime, monotonic: Duration) -> bool {
        if let Some((previous_wall, previous_monotonic)) = self.previous {
            let drift = monotonic
                .checked_sub(previous_monotonic)
                .and_then(|elapsed| previous_wall.checked_add(elapsed))
                .map(|expected_wall| absolute_time_difference(expected_wall, wall));
            self.last_drift = drift.unwrap_or(Duration::MAX);
            if match drift {
                Some(drift) => drift > self.threshold,
                None => true,
            } {
                self.paused = true;
            }
        }
        self.previous = Some((wall, monotonic));
        self.paused
    }

    fn last_drift(&self) -> Duration {
        self.last_drift
    }
}

fn absolute_time_difference(left: SystemTime, right: SystemTime) -> Duration {
    left.duration_since(right)
        .or_else(|_| right.duration_since(left))
        .unwrap_or(Duration::MAX)
}

pub fn delete_queue_capacity(config: &Config) -> usize {
    config.delete_rate.max(config.delete_concurrency)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatedOutcome {
    Retired(RetirementOutcome),
    Renewed,
    Stale,
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueError {
    NotRunning,
    Full,
    AlreadyQueued,
}

struct RetirementJob {
    candidate: ExpiryCandidate,
    durability: RetirementDurability,
    prepared: bool,
    attempt: u32,
    not_before: Instant,
    completion: Option<oneshot::Sender<io::Result<CoordinatedOutcome>>>,
    retirement: Option<Arc<RetirementRecord>>,
    _admission: OwnedSemaphorePermit,
}

#[derive(Clone)]
struct SharedIoError {
    kind: io::ErrorKind,
    message: String,
}

#[derive(Clone)]
struct RetirementNotice {
    result: Option<Result<CoordinatedOutcome, SharedIoError>>,
    terminal: bool,
}

struct RetirementRecord {
    durability: RetirementDurability,
    notice: watch::Sender<RetirementNotice>,
}

impl RetirementRecord {
    fn new(durability: RetirementDurability) -> Self {
        let (notice, _) = watch::channel(RetirementNotice {
            result: None,
            terminal: false,
        });
        Self { durability, notice }
    }

    fn satisfies(&self, requested: RetirementDurability) -> bool {
        requested == RetirementDurability::Expiry
            || self.durability == RetirementDurability::Explicit
    }

    fn subscribe(self: &Arc<Self>) -> RetirementWait {
        RetirementWait {
            notice: self.notice.subscribe(),
        }
    }

    fn publish(&self, result: &io::Result<CoordinatedOutcome>, terminal: bool) {
        let result = match result {
            Ok(outcome) => Ok(*outcome),
            Err(error) => Err(SharedIoError {
                kind: error.kind(),
                message: error.to_string(),
            }),
        };
        self.notice.send_modify(|notice| {
            notice.result = Some(result);
            notice.terminal = terminal;
        });
    }
}

struct RetirementWait {
    notice: watch::Receiver<RetirementNotice>,
}

enum RetirementRegistration {
    New {
        record: Arc<RetirementRecord>,
        wait: RetirementWait,
    },
    Joined(RetirementWait),
}

struct RetirementEntry {
    candidate: ExpiryCandidate,
    record: Arc<RetirementRecord>,
}

impl RetirementEntry {
    fn matches(&self, candidate: &ExpiryCandidate) -> bool {
        self.candidate.stream_id() == candidate.stream_id()
            && Arc::ptr_eq(&self.candidate.stream(), &candidate.stream())
    }
}

#[derive(Default)]
struct RetirementRegistry {
    entries: Mutex<HashMap<u64, RetirementEntry>>,
}

impl RetirementRegistry {
    /// Own the queue marker and publish its shared completion entry under one
    /// mutex. An exact join can therefore never observe the marker without the
    /// entry it needs to wait on.
    fn register(
        &self,
        candidate: &ExpiryCandidate,
        durability: RetirementDurability,
        join_existing: bool,
    ) -> Result<RetirementRegistration, EnqueueError> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = entries.get(&candidate.stream_id()) {
            if join_existing && entry.matches(candidate) && entry.record.satisfies(durability) {
                return Ok(RetirementRegistration::Joined(entry.record.subscribe()));
            }
            return Err(EnqueueError::AlreadyQueued);
        }
        if !candidate.try_mark_queued() {
            return Err(EnqueueError::AlreadyQueued);
        }
        let record = Arc::new(RetirementRecord::new(durability));
        let wait = record.subscribe();
        entries.insert(
            candidate.stream_id(),
            RetirementEntry {
                candidate: candidate.clone(),
                record: Arc::clone(&record),
            },
        );
        Ok(RetirementRegistration::New { record, wait })
    }

    /// Extend one admitted retirement across an exact parent cascade. Marker
    /// ownership and publication of the parent's join row share the same mutex
    /// as ordinary registration, so a waiter cannot observe one without the
    /// other. Every generation points at the root record and its durability.
    fn register_cascade(
        &self,
        store: &Store,
        record: &Arc<RetirementRecord>,
        cascade: &ExpiryCandidate,
    ) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !entries
            .values()
            .any(|entry| Arc::ptr_eq(&entry.record, record))
        {
            return false;
        }
        if let Some(entry) = entries.get(&cascade.stream_id()) {
            return Arc::ptr_eq(&entry.record, record) && entry.matches(cascade);
        }
        if !store.is_current(cascade) {
            return false;
        }
        if !cascade.try_mark_queued() {
            return false;
        }
        entries.insert(
            cascade.stream_id(),
            RetirementEntry {
                candidate: cascade.clone(),
                record: Arc::clone(record),
            },
        );
        true
    }

    /// Keep the exact soft-delete owner alive when a concurrent child
    /// retirement has durably dropped its refcount to zero. This check and the
    /// marker restoration share the registry mutex with cascade registration,
    /// so the transferred continuation cannot fall between row removal and a
    /// fresh admission.
    fn retain_zero_ref_soft_continuation(
        &self,
        store: &Store,
        record: &Arc<RetirementRecord>,
        candidate: &ExpiryCandidate,
    ) -> bool {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(entry) = entries.get(&candidate.stream_id()) else {
            return false;
        };
        Arc::ptr_eq(&entry.record, record)
            && entry.matches(candidate)
            && store.retain_zero_ref_soft_retirement(candidate)
    }

    fn cancel_admission(&self, record: &Arc<RetirementRecord>, error: &io::Error) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        record.publish(&Err(io::Error::new(error.kind(), error.to_string())), true);
        entries.retain(|_, entry| {
            let keep = !Arc::ptr_eq(&entry.record, record);
            if !keep {
                entry.candidate.clear_queued();
            }
            keep
        });
    }

    fn publish(
        &self,
        record: &Arc<RetirementRecord>,
        result: &io::Result<CoordinatedOutcome>,
        terminal: bool,
    ) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        record.publish(result, terminal);
        if terminal {
            entries.retain(|_, entry| !Arc::ptr_eq(&entry.record, record));
        }
    }

    fn fail_all(&self, message: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let error = io::Error::other(message.to_owned());
        for entry in entries.values() {
            entry
                .record
                .publish(&Err(io::Error::new(error.kind(), error.to_string())), true);
            entry.candidate.clear_queued();
        }
        entries.clear();
    }
}

struct Coordinator {
    tx: mpsc::Sender<RetirementJob>,
    admission: Arc<Semaphore>,
    accepting: AtomicBool,
    stats: Arc<Stats>,
    store: Weak<Store>,
    retirements: Arc<RetirementRegistry>,
}

/// Safety state deliberately lives above an individual scanner task. A
/// supervisor restart must not buy a fresh startup grace period or clear a
/// process-lifetime bulk/clock latch.
struct ScannerState {
    started: Instant,
    expiry_cursor: ExpiryScanCursor,
    recovered_cursor: ExpiryScanCursor,
    recovered_complete: bool,
    recovered_pass_admitted_all: bool,
    gate: DeleteGate,
    clock: ClockGuard,
    pass_oldest_due_deadline: Option<SystemTime>,
}

impl ScannerState {
    fn new(config: Config) -> Self {
        let mut clock = ClockGuard::new(config.clock_jump);
        let _ = clock.observe(SystemTime::now(), Duration::ZERO);
        Self {
            started: Instant::now(),
            expiry_cursor: ExpiryScanCursor::default(),
            recovered_cursor: ExpiryScanCursor::default(),
            recovered_complete: false,
            recovered_pass_admitted_all: true,
            gate: DeleteGate::new(config, Duration::ZERO),
            clock,
            pass_oldest_due_deadline: None,
        }
    }

    fn record_recovered_page(
        &mut self,
        completed_pass: bool,
        admitted_all: bool,
        recovered_index_empty: bool,
    ) {
        self.recovered_pass_admitted_all &= admitted_all;
        if completed_pass {
            // A lossless full pass transfers every recovered candidate to the
            // bounded coordinator. Physical retirement may keep failing and be
            // quarantined; pinning the scanner on that non-empty recovery index
            // would starve ordinary live expiry without adding safety or bounds.
            if self.recovered_pass_admitted_all || recovered_index_empty {
                self.recovered_complete = true;
            }
            self.recovered_pass_admitted_all = true;
        }
    }
}

static COORDINATOR: OnceLock<Coordinator> = OnceLock::new();

#[cfg(test)]
static PANIC_SCANNER_ONCE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
struct RetireAfterFinishHook {
    path: String,
    triggered: AtomicBool,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
static RETIRE_AFTER_FINISH_HOOK: Mutex<Option<Arc<RetireAfterFinishHook>>> = Mutex::new(None);

#[cfg(test)]
struct RetireAfterFinishHookGuard {
    hook: Arc<RetireAfterFinishHook>,
}

#[cfg(test)]
impl RetireAfterFinishHookGuard {
    async fn reached(&self) {
        self.hook.reached.notified().await;
    }

    fn release(&self) {
        self.hook.release.notify_one();
    }
}

#[cfg(test)]
impl Drop for RetireAfterFinishHookGuard {
    fn drop(&mut self) {
        self.hook.release.notify_one();
        let mut installed = RETIRE_AFTER_FINISH_HOOK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if installed
            .as_ref()
            .is_some_and(|hook| Arc::ptr_eq(hook, &self.hook))
        {
            *installed = None;
        }
    }
}

#[cfg(test)]
fn install_retire_after_finish_hook(path: &str) -> RetireAfterFinishHookGuard {
    let hook = Arc::new(RetireAfterFinishHook {
        path: path.to_owned(),
        triggered: AtomicBool::new(false),
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let mut installed = RETIRE_AFTER_FINISH_HOOK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(
        installed.is_none(),
        "a retirement test hook is already installed"
    );
    *installed = Some(Arc::clone(&hook));
    RetireAfterFinishHookGuard { hook }
}

#[cfg(test)]
async fn pause_after_retirement_finish(candidate: &ExpiryCandidate) {
    let hook = RETIRE_AFTER_FINISH_HOOK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if let Some(hook) = hook.filter(|hook| {
        hook.path == candidate.stream().path
            && hook
                .triggered
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }) {
        hook.reached.notify_one();
        hook.release.notified().await;
    }
}

struct Stats {
    mode: Mode,
    queue_capacity: usize,
    index_entries: AtomicUsize,
    scan_checked: AtomicU64,
    due: AtomicU64,
    completed_passes: AtomicU64,
    last_pass_checked: AtomicU64,
    last_pass_due: AtomicU64,
    oldest_due_lag_micros: AtomicU64,
    cursor: AtomicU64,
    queue_depth: AtomicUsize,
    active: AtomicUsize,
    retries: AtomicU64,
    quarantined_retirements: AtomicU64,
    scanner_restarts: AtomicU64,
    outcomes_reaped: AtomicU64,
    outcomes_soft_deleted: AtomicU64,
    outcomes_renewed: AtomicU64,
    outcomes_stale: AtomicU64,
    failures: AtomicU64,
    pause: AtomicU8,
    last_scan_unix: AtomicU64,
    last_cleanup_unix: AtomicU64,
}

impl Stats {
    fn new(mode: Mode, queue_capacity: usize) -> Self {
        Self {
            mode,
            queue_capacity,
            index_entries: AtomicUsize::new(0),
            scan_checked: AtomicU64::new(0),
            due: AtomicU64::new(0),
            completed_passes: AtomicU64::new(0),
            last_pass_checked: AtomicU64::new(0),
            last_pass_due: AtomicU64::new(0),
            oldest_due_lag_micros: AtomicU64::new(u64::MAX),
            cursor: AtomicU64::new(0),
            queue_depth: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            retries: AtomicU64::new(0),
            quarantined_retirements: AtomicU64::new(0),
            scanner_restarts: AtomicU64::new(0),
            outcomes_reaped: AtomicU64::new(0),
            outcomes_soft_deleted: AtomicU64::new(0),
            outcomes_renewed: AtomicU64::new(0),
            outcomes_stale: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            pause: AtomicU8::new(0),
            last_scan_unix: AtomicU64::new(0),
            last_cleanup_unix: AtomicU64::new(0),
        }
    }

    fn record_pause(&self, bulk: bool, clock: bool) {
        let value = u8::from(bulk) | (u8::from(clock) << 1);
        self.pause.store(value, Ordering::Release);
        crate::telemetry::set_expiry_safety_pauses(bulk, clock);
    }

    fn record_queue(&self) {
        crate::telemetry::record_expiry_queue(
            self.queue_depth.load(Ordering::Relaxed) as u64,
            self.active.load(Ordering::Relaxed) as u64,
        );
    }

    fn record_outcome(&self, result: &io::Result<CoordinatedOutcome>) {
        match result {
            Ok(CoordinatedOutcome::Retired(RetirementOutcome::Reaped)) => {
                crate::telemetry::record_expiry_outcome("reaped");
                self.outcomes_reaped.fetch_add(1, Ordering::Relaxed);
                self.last_cleanup_unix
                    .store(unix_seconds(), Ordering::Relaxed);
            }
            Ok(CoordinatedOutcome::Retired(RetirementOutcome::SoftDeleted)) => {
                crate::telemetry::record_expiry_outcome("soft_deleted");
                self.outcomes_soft_deleted.fetch_add(1, Ordering::Relaxed);
                self.last_cleanup_unix
                    .store(unix_seconds(), Ordering::Relaxed);
            }
            Ok(CoordinatedOutcome::Stale) => {
                crate::telemetry::record_expiry_outcome("stale");
                self.outcomes_stale.fetch_add(1, Ordering::Relaxed);
            }
            Ok(CoordinatedOutcome::Renewed) => {
                crate::telemetry::record_expiry_outcome("renewed");
                self.outcomes_renewed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(CoordinatedOutcome::Gone) => {
                crate::telemetry::record_expiry_outcome("stale");
                self.outcomes_stale.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                crate::telemetry::record_expiry_outcome("failed");
                self.failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Serialize)]
pub struct Status {
    mode: &'static str,
    index_entries: usize,
    scan_checked: u64,
    due: u64,
    completed_passes: u64,
    last_completed_pass_checked: u64,
    last_completed_pass_due: u64,
    due_fraction: Option<f64>,
    oldest_due_age_seconds: Option<f64>,
    cursor: Option<u64>,
    queue_depth: usize,
    queue_capacity: usize,
    active_cleanup_workers: usize,
    retries: u64,
    quarantined_retirements: u64,
    scanner_restarts: u64,
    reaped: u64,
    soft_deleted: u64,
    renewed: u64,
    stale: u64,
    failures: u64,
    paused: Option<&'static str>,
    last_scan_unix: Option<u64>,
    last_cleanup_unix: Option<u64>,
}

pub fn status() -> Option<Status> {
    let coordinator = COORDINATOR.get()?;
    let stats = &coordinator.stats;
    let nonzero = |value| (value != 0).then_some(value);
    let pass_checked = stats.last_pass_checked.load(Ordering::Relaxed);
    let pass_due = stats.last_pass_due.load(Ordering::Relaxed);
    let oldest_due_lag_micros = stats.oldest_due_lag_micros.load(Ordering::Relaxed);
    Some(Status {
        mode: match stats.mode {
            Mode::Off => "off",
            Mode::Observe => "observe",
            Mode::Delete => "delete",
        },
        index_entries: coordinator.store.upgrade().map_or_else(
            || stats.index_entries.load(Ordering::Relaxed),
            |store| store.expiring_stream_count(),
        ),
        scan_checked: stats.scan_checked.load(Ordering::Relaxed),
        due: stats.due.load(Ordering::Relaxed),
        completed_passes: stats.completed_passes.load(Ordering::Relaxed),
        last_completed_pass_checked: pass_checked,
        last_completed_pass_due: pass_due,
        due_fraction: (pass_checked != 0).then_some(pass_due as f64 / pass_checked as f64),
        oldest_due_age_seconds: (oldest_due_lag_micros != u64::MAX)
            .then_some(oldest_due_lag_micros as f64 / 1_000_000.0),
        cursor: nonzero(stats.cursor.load(Ordering::Relaxed)),
        queue_depth: stats.queue_depth.load(Ordering::Relaxed),
        queue_capacity: stats.queue_capacity,
        active_cleanup_workers: stats.active.load(Ordering::Relaxed),
        retries: stats.retries.load(Ordering::Relaxed),
        quarantined_retirements: stats.quarantined_retirements.load(Ordering::Relaxed),
        scanner_restarts: stats.scanner_restarts.load(Ordering::Relaxed),
        reaped: stats.outcomes_reaped.load(Ordering::Relaxed),
        soft_deleted: stats.outcomes_soft_deleted.load(Ordering::Relaxed),
        renewed: stats.outcomes_renewed.load(Ordering::Relaxed),
        stale: stats.outcomes_stale.load(Ordering::Relaxed),
        failures: stats.failures.load(Ordering::Relaxed),
        paused: match stats.pause.load(Ordering::Relaxed) {
            1 => Some("bulk"),
            2 => Some("clock"),
            3 => Some("bulk+clock"),
            _ => None,
        },
        last_scan_unix: nonzero(stats.last_scan_unix.load(Ordering::Relaxed)),
        last_cleanup_unix: nonzero(stats.last_cleanup_unix.load(Ordering::Relaxed)),
    })
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn try_send_counted<T>(tx: &mpsc::Sender<T>, stats: &Stats, job: T) -> Result<(), T> {
    // Publish the accounting before the job: after a successful channel send,
    // the dispatcher may run immediately and subtract without underflowing.
    stats.queue_depth.fetch_add(1, Ordering::Relaxed);
    if let Err(error) = tx.try_send(job) {
        stats.queue_depth.fetch_sub(1, Ordering::Relaxed);
        stats.record_queue();
        return Err(error.into_inner());
    }
    stats.record_queue();
    Ok(())
}

fn publish_retirement(
    retirements: Option<&RetirementRegistry>,
    record: Option<&Arc<RetirementRecord>>,
    result: &io::Result<CoordinatedOutcome>,
    terminal: bool,
) {
    if let (Some(retirements), Some(record)) = (retirements, record) {
        retirements.publish(record, result, terminal);
    }
}

fn register_and_enqueue(
    candidate: ExpiryCandidate,
    durability: RetirementDurability,
    completion: Option<oneshot::Sender<io::Result<CoordinatedOutcome>>>,
    prepared: bool,
    join_existing: bool,
) -> Result<RetirementRegistration, EnqueueError> {
    let coordinator = COORDINATOR.get().ok_or(EnqueueError::NotRunning)?;
    if !coordinator.accepting.load(Ordering::Acquire) {
        return Err(EnqueueError::NotRunning);
    }
    let registration = coordinator
        .retirements
        .register(&candidate, durability, join_existing)?;
    let (record, wait) = match registration {
        RetirementRegistration::Joined(wait) => {
            return Ok(RetirementRegistration::Joined(wait));
        }
        RetirementRegistration::New { record, wait } => (record, wait),
    };
    let admission = Arc::clone(&coordinator.admission)
        .try_acquire_owned()
        .map_err(|_| {
            coordinator.retirements.cancel_admission(
                &record,
                &io::Error::new(io::ErrorKind::WouldBlock, "retirement admission is full"),
            );
            EnqueueError::Full
        })?;
    let job = RetirementJob {
        candidate,
        durability,
        prepared,
        attempt: 0,
        not_before: Instant::now(),
        completion,
        retirement: Some(Arc::clone(&record)),
        _admission: admission,
    };
    if let Err(job) = try_send_counted(&coordinator.tx, &coordinator.stats, job) {
        coordinator.retirements.cancel_admission(
            &record,
            &io::Error::new(io::ErrorKind::WouldBlock, "retirement queue is unavailable"),
        );
        drop(job);
        return Err(EnqueueError::Full);
    }
    Ok(RetirementRegistration::New { record, wait })
}

fn enqueue(
    candidate: ExpiryCandidate,
    durability: RetirementDurability,
    completion: Option<oneshot::Sender<io::Result<CoordinatedOutcome>>>,
    prepared: bool,
) -> Result<(), EnqueueError> {
    match register_and_enqueue(candidate, durability, completion, prepared, false)? {
        RetirementRegistration::New { .. } => Ok(()),
        RetirementRegistration::Joined(_) => unreachable!("joining was not requested"),
    }
}

/// Queue lazy/proactive expiry without blocking the request path. A full queue
/// leaves the stream discoverable for the next scan; no detached fallback task
/// is spawned.
pub fn enqueue_expired(candidate: ExpiryCandidate) -> Result<(), EnqueueError> {
    enqueue(candidate, RetirementDurability::Expiry, None, false)
}

/// Enter the same bounded coordinator as proactive cleanup and await this
/// request's result. Used by explicit DELETE and expired PUT path reuse.
pub async fn retire_and_wait(
    candidate: ExpiryCandidate,
    durability: RetirementDurability,
) -> io::Result<CoordinatedOutcome> {
    let (tx, rx) = oneshot::channel();
    enqueue(candidate, durability, Some(tx), false).map_err(|error| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("retirement coordinator unavailable: {error:?}"),
        )
    })?;
    rx.await
        .map_err(|_| io::Error::other("retirement coordinator stopped"))?
}

async fn wait_for_retirement(
    mut wait: RetirementWait,
    timeout: Duration,
) -> io::Result<CoordinatedOutcome> {
    tokio::time::timeout(timeout, async move {
        loop {
            let notice = wait.notice.borrow_and_update().clone();
            if notice.terminal {
                let result = notice
                    .result
                    .expect("published retirement notice contains a result");
                return result.map_err(|error| io::Error::new(error.kind, error.message));
            }
            wait.notice
                .changed()
                .await
                .map_err(|_| io::Error::other("retirement coordinator stopped"))?;
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "retirement wait timed out"))?
}

/// Admit this exact retirement or join the already-admitted incarnation. This
/// is used by expired PUT path reuse: it never replaces or downgrades an
/// existing explicit-delete job, and the request wait is bounded while the
/// coordinator retains retry ownership through success or finite quarantine.
pub async fn retire_or_join_and_wait(
    candidate: ExpiryCandidate,
    durability: RetirementDurability,
) -> io::Result<CoordinatedOutcome> {
    let registration =
        register_and_enqueue(candidate, durability, None, false, true).map_err(|error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("retirement coordinator unavailable: {error:?}"),
            )
        })?;
    let wait = match registration {
        RetirementRegistration::New { wait, .. } | RetirementRegistration::Joined(wait) => wait,
    };
    wait_for_retirement(wait, RETIREMENT_WAIT_TIMEOUT).await
}

pub struct Handle {
    stop: watch::Sender<bool>,
    stopped: oneshot::Receiver<()>,
    join: JoinHandle<()>,
    admission: Arc<Semaphore>,
}

impl Handle {
    pub async fn stopped(&mut self) {
        let _ = (&mut self.stopped).await;
    }

    pub async fn shutdown(self) {
        if let Some(coordinator) = COORDINATOR.get() {
            coordinator.accepting.store(false, Ordering::Release);
        }
        self.admission.close();
        let _ = self.stop.send(true);
        let _ = self.join.await;
    }
}

pub fn spawn(store: Arc<Store>, config: Config) -> Handle {
    let capacity = delete_queue_capacity(&config);
    let (tx, rx) = mpsc::channel(capacity);
    let admission = Arc::new(Semaphore::new(capacity));
    let stats = Arc::new(Stats::new(config.mode, capacity));
    let initial_index_entries = store.expiring_stream_count();
    stats
        .index_entries
        .store(initial_index_entries, Ordering::Relaxed);
    crate::telemetry::record_expiry_index_entries(initial_index_entries as u64);
    let retirements = Arc::new(RetirementRegistry::default());
    COORDINATOR
        .set(Coordinator {
            tx,
            admission: Arc::clone(&admission),
            accepting: AtomicBool::new(true),
            stats: Arc::clone(&stats),
            store: Arc::downgrade(&store),
            retirements: Arc::clone(&retirements),
        })
        .unwrap_or_else(|_| panic!("expiration coordinator already started"));

    let (stop, stop_rx) = watch::channel(false);
    let (stopped_tx, stopped) = oneshot::channel();
    let join = tokio::spawn(async move {
        run(store, config, rx, stop_rx, stats, retirements).await;
        let _ = stopped_tx.send(());
    });
    Handle {
        stop,
        stopped,
        join,
        admission,
    }
}

async fn run(
    store: Arc<Store>,
    config: Config,
    rx: mpsc::Receiver<RetirementJob>,
    stop: watch::Receiver<bool>,
    stats: Arc<Stats>,
    retirements: Arc<RetirementRegistry>,
) {
    let mut stop_observer = stop.clone();
    let mut scanner = tokio::spawn(supervise_scanner(
        Arc::clone(&store),
        config.clone(),
        stop.clone(),
        Arc::clone(&stats),
        Arc::new(Mutex::new(ScannerState::new(config.clone()))),
    ));
    let mut dispatcher = tokio::spawn(dispatch_loop(
        store,
        config,
        rx,
        stop,
        stats,
        Some(retirements),
    ));
    tokio::select! {
        result = &mut scanner => {
            let expected_shutdown = *stop_observer.borrow_and_update();
            if !expected_shutdown {
                tracing::error!(?result, "expiration scanner stopped unexpectedly");
                dispatcher.abort();
            }
            let _ = dispatcher.await;
        }
        result = &mut dispatcher => {
            let expected_shutdown = *stop_observer.borrow_and_update();
            if !expected_shutdown {
                tracing::error!(?result, "expiration retirement dispatcher stopped unexpectedly");
                scanner.abort();
            }
            let _ = scanner.await;
        }
    }
    if let Some(coordinator) = COORDINATOR.get() {
        coordinator
            .retirements
            .fail_all("retirement coordinator stopped");
    }
}

async fn supervise_scanner(
    store: Arc<Store>,
    config: Config,
    mut stop: watch::Receiver<bool>,
    stats: Arc<Stats>,
    state: Arc<Mutex<ScannerState>>,
) {
    let mut backoff = Duration::from_millis(100);
    loop {
        let mut scanner = tokio::spawn(scan_loop(
            Arc::clone(&store),
            config.clone(),
            stop.clone(),
            Arc::clone(&stats),
            Arc::clone(&state),
        ));
        tokio::select! {
            changed = stop.changed() => {
                scanner.abort();
                let _ = scanner.await;
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            result = &mut scanner => {
                if *stop.borrow() {
                    return;
                }
                stats.scanner_restarts.fetch_add(1, Ordering::Relaxed);
                tracing::error!(?result, "expiration scanner stopped; restarting");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() {
                            return;
                        }
                    }
                }
                backoff = backoff.saturating_mul(2).min(Duration::from_secs(10));
            }
        }
    }
}

async fn scan_loop(
    store: Arc<Store>,
    config: Config,
    mut stop: watch::Receiver<bool>,
    stats: Arc<Stats>,
    state: Arc<Mutex<ScannerState>>,
) {
    #[cfg(test)]
    if PANIC_SCANNER_ONCE.swap(false, Ordering::AcqRel) {
        panic!("injected expiration scanner failure");
    }
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                let now = SystemTime::now();
                // Recovery-created, abandoned soft tombstones are invisible to
                // request lookup. Seed them through the same bounded admission
                // and paced dispatcher in every mode before proactive scanning.
                let recovered = {
                    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                    if state.recovered_complete {
                        None
                    } else {
                        let page = store.scan_recovered_retirements(
                            &mut state.recovered_cursor,
                            config.scan_rate,
                        );
                        Some(page)
                    }
                };
                if let Some(page) = recovered {
                    let mut admitted_all = true;
                    for candidate in page.due {
                        match enqueue(candidate, RetirementDurability::Expiry, None, true) {
                            Ok(()) | Err(EnqueueError::AlreadyQueued) => {}
                            Err(EnqueueError::Full) => {
                                admitted_all = false;
                                break;
                            }
                            Err(EnqueueError::NotRunning) => return,
                        }
                    }
                    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                    state.record_recovered_page(
                        page.completed_pass,
                        admitted_all,
                        store.recovered_retirement_count() == 0,
                    );
                    continue;
                }

                if config.mode == Mode::Off {
                    let entries = store.expiring_stream_count();
                    stats.index_entries.store(entries, Ordering::Relaxed);
                    crate::telemetry::record_expiry_index_entries(entries as u64);
                    continue;
                }

                let scan_started = Instant::now();
                let (page, may_delete, bulk_paused, clock_paused, cursor, completed_totals, oldest_due_lag, clock_drift) = {
                    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                    let elapsed = state.started.elapsed();
                    let clock_paused = state.clock.observe(now, elapsed);
                    let clock_drift = state.clock.last_drift();
                    let page = store.scan_expiring(&mut state.expiry_cursor, config.scan_rate, now);
                    if let Some(deadline) = page.oldest_due_deadline {
                        state.pass_oldest_due_deadline = match state.pass_oldest_due_deadline {
                            Some(oldest) => Some(oldest.min(deadline)),
                            None => Some(deadline),
                        };
                    }
                    let completed_totals = page.completed_pass.then_some((
                        state.gate.pass_checked.saturating_add(page.checked),
                        state.gate.pass_due.saturating_add(page.due.len()),
                    ));
                    let oldest_due_lag = page.completed_pass.then(|| {
                        state
                            .pass_oldest_due_deadline
                            .and_then(|deadline| now.duration_since(deadline).ok())
                            .map(|lag| lag.as_secs_f64())
                    });
                    let may_delete = state.gate.observe_page(
                        elapsed,
                        page.checked,
                        page.due.len(),
                        page.completed_pass,
                    ) && !clock_paused;
                    if page.completed_pass {
                        state.pass_oldest_due_deadline = None;
                    }
                    let bulk_paused = state.gate.pause() == Some(PauseReason::Bulk);
                    let cursor = state.expiry_cursor.after().unwrap_or(0);
                    (
                        page,
                        may_delete,
                        bulk_paused,
                        clock_paused,
                        cursor,
                        completed_totals,
                        oldest_due_lag,
                        clock_drift,
                    )
                };
                crate::telemetry::record_expiry_clock_drift(clock_drift.as_secs_f64());
                crate::telemetry::record_expiry_scan(
                    page.checked as u64,
                    page.due.len() as u64,
                    scan_started.elapsed().as_secs_f64(),
                );
                let entries = store.expiring_stream_count();
                stats.index_entries.store(entries, Ordering::Relaxed);
                crate::telemetry::record_expiry_index_entries(entries as u64);
                stats.scan_checked.fetch_add(page.checked as u64, Ordering::Relaxed);
                stats.due.fetch_add(page.due.len() as u64, Ordering::Relaxed);
                stats.cursor.store(cursor, Ordering::Relaxed);
                stats.last_scan_unix.store(unix_seconds(), Ordering::Relaxed);
                if page.completed_pass {
                    stats.completed_passes.fetch_add(1, Ordering::Relaxed);
                }
                if let Some((checked, due)) = completed_totals {
                    crate::telemetry::record_expiry_completed_pass(checked as u64, due as u64);
                    crate::telemetry::record_expiry_oldest_due_lag(oldest_due_lag.flatten());
                    stats
                        .last_pass_checked
                        .store(checked as u64, Ordering::Relaxed);
                    stats
                        .last_pass_due
                        .store(due as u64, Ordering::Relaxed);
                    stats.oldest_due_lag_micros.store(
                        oldest_due_lag
                            .flatten()
                            .map_or(u64::MAX, |seconds| {
                                (seconds * 1_000_000.0).min(u64::MAX as f64) as u64
                            }),
                        Ordering::Relaxed,
                    );
                }
                stats.record_pause(bulk_paused, clock_paused);
                if config.mode == Mode::Observe {
                    for _ in &page.due {
                        crate::telemetry::record_expiry_outcome("observe");
                    }
                }
                if may_delete {
                    for candidate in page.due {
                        match enqueue_expired(candidate) {
                            Ok(()) | Err(EnqueueError::AlreadyQueued) => {}
                            Err(EnqueueError::Full) => {
                                tracing::error!("expiration retirement queue is full; candidate will be retried by scanning");
                                break;
                            }
                            Err(EnqueueError::NotRunning) => return,
                        }
                    }
                }
            }
        }
    }
}

async fn dispatch_loop(
    store: Arc<Store>,
    config: Config,
    mut rx: mpsc::Receiver<RetirementJob>,
    mut stop: watch::Receiver<bool>,
    stats: Arc<Stats>,
    retirements: Option<Arc<RetirementRegistry>>,
) {
    let nanos = (1_000_000_000u128 / config.delete_rate as u128).max(1) as u64;
    let mut pace = tokio::time::interval(Duration::from_nanos(nanos));
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    pace.tick().await;
    let mut active: JoinSet<io::Result<RetirementAttempt>> = JoinSet::new();
    let mut active_jobs: HashMap<tokio::task::Id, RetirementJob> = HashMap::new();
    let mut retries = VecDeque::new();
    let mut draining = false;

    loop {
        if draining && active.is_empty() && retries.is_empty() && rx.is_empty() {
            return;
        }
        tokio::select! {
            changed = stop.changed(), if !draining => {
                if changed.is_err() || *stop.borrow() {
                    draining = true;
                    rx.close();
                }
            }
            Some(joined) = active.join_next_with_id(), if !active.is_empty() => {
                stats.active.fetch_sub(1, Ordering::Relaxed);
                stats.record_queue();
                let (mut job, result) = match joined {
                    Ok((id, result)) => (
                        active_jobs.remove(&id).expect("active retirement job exists"),
                        result,
                    ),
                    Err(error) => {
                        let id = error.id();
                        let job = active_jobs
                            .remove(&id)
                            .expect("panicked retirement job remains tracked");
                        (job, Err(io::Error::other(format!("retirement task failed: {error}"))))
                    }
                };
                match result {
                    Ok(attempt) => {
                        stats.record_outcome(&Ok(attempt.outcome));
                        let retained_soft_continuation = matches!(
                            attempt.outcome,
                            CoordinatedOutcome::Retired(RetirementOutcome::SoftDeleted)
                        ) && job.retirement.as_ref().is_some_and(|record| {
                            retirements.as_ref().is_some_and(|retirements| {
                                retirements.retain_zero_ref_soft_continuation(
                                    &store,
                                    record,
                                    &job.candidate,
                                )
                            })
                        });
                        if retained_soft_continuation {
                            // A last-child cleanup raced this physical soft
                            // delete and transferred its now-zero-reference
                            // parent continuation to our exact registry row.
                            // Keep this admission, completion, and durability;
                            // the tombstone is already fenced/prepared.
                            job.prepared = true;
                            job.attempt = 0;
                            job.not_before = Instant::now();
                            stats.queue_depth.fetch_add(1, Ordering::Relaxed);
                            stats.record_queue();
                            retries.push_back(job);
                        } else if let Some(cascade) = attempt.cascade {
                            let owns_cascade = match job.retirement.as_ref() {
                                Some(record) => retirements.as_ref().is_some_and(|retirements| {
                                    retirements.register_cascade(&store, record, &cascade)
                                }),
                                None => cascade.try_mark_queued(),
                            };
                            if owns_cascade {
                                job.candidate = cascade;
                                job.prepared = true;
                                job.attempt = 0;
                                job.not_before = Instant::now();
                                stats.queue_depth.fetch_add(1, Ordering::Relaxed);
                                stats.record_queue();
                                retries.push_back(job);
                            } else {
                                // Cascade ownership is secondary: an exact
                                // parent marker may belong to an active job or
                                // to the finite-retry quarantine. Transfer the
                                // parent continuation to that existing owner,
                                // publish only this completed child step, and
                                // never clear the other owner's marker. This is
                                // terminal for this admission even while
                                // draining, so a conflict cannot retain queue
                                // capacity or hang shutdown.
                                tracing::debug!(
                                    stream_id = cascade.stream_id(),
                                    "expiration cascade transferred to existing exact owner"
                                );
                                let result = Ok(attempt.outcome);
                                publish_retirement(
                                    retirements.as_deref(),
                                    job.retirement.as_ref(),
                                    &result,
                                    true,
                                );
                                if let Some(completion) = job.completion.take() {
                                    let _ = completion.send(result);
                                }
                            }
                        } else {
                            let result = Ok(attempt.outcome);
                            publish_retirement(
                                retirements.as_deref(),
                                job.retirement.as_ref(),
                                &result,
                                true,
                            );
                            if let Some(completion) = job.completion.take() {
                                let _ = completion.send(result);
                            }
                        }
                    }
                    Err(error) => {
                        stats.record_outcome(&Err(io::Error::new(error.kind(), error.to_string())));
                        let next_attempt = job.attempt.saturating_add(1);
                        let exhausted = !draining && next_attempt >= MAX_RETIREMENT_ATTEMPTS;
                        // The waiting request receives the failure, but the same
                        // bounded admission stays owned by this job and retries
                        // in the background. In particular an explicit DELETE
                        // is never later downgraded to expiry durability.
                        if draining {
                            job.candidate.clear_queued();
                            let reported = Err(io::Error::new(error.kind(), error.to_string()));
                            publish_retirement(
                                retirements.as_deref(),
                                job.retirement.as_ref(),
                                &reported,
                                true,
                            );
                        } else if exhausted {
                            // Keep the exact candidate's queue marker latched as
                            // a process-lifetime quarantine. This prevents the
                            // scanner from hot-loop re-admitting it, while
                            // dropping the job below releases its bounded permit
                            // for unrelated work. Recovery reconstructs markers
                            // on restart and can safely try the indexed stream
                            // again.
                            let reported = Err(io::Error::new(error.kind(), error.to_string()));
                            publish_retirement(
                                retirements.as_deref(),
                                job.retirement.as_ref(),
                                &reported,
                                true,
                            );
                            stats
                                .quarantined_retirements
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::error!(
                                stream_id = job.candidate.stream_id(),
                                attempts = next_attempt,
                                %error,
                                "expiration retirement exhausted retry budget; quarantined until restart"
                            );
                        } else {
                            let reported = Err(io::Error::new(error.kind(), error.to_string()));
                            publish_retirement(
                                retirements.as_deref(),
                                job.retirement.as_ref(),
                                &reported,
                                false,
                            );
                        }
                        if let Some(completion) = job.completion.take() {
                            let reported = io::Error::new(error.kind(), error.to_string());
                            let _ = completion.send(Err(reported));
                        }
                        if !draining && !exhausted {
                            job.attempt = next_attempt;
                            let seconds = 1u64 << job.attempt.min(6);
                            job.not_before = Instant::now() + Duration::from_secs(seconds);
                            stats.retries.fetch_add(1, Ordering::Relaxed);
                            crate::telemetry::record_expiry_retry();
                            stats.queue_depth.fetch_add(1, Ordering::Relaxed);
                            stats.record_queue();
                            retries.push_back(job);
                        }
                    }
                }
            }
            _ = pace.tick(), if active.len() < config.delete_concurrency => {
                let now = Instant::now();
                let mut job = if draining {
                    // Shutdown drains already-admitted retry/continuation work
                    // first, then falls back to the buffered receiver. Never let
                    // `draining` turn an empty retry deque into rx starvation.
                    retries.pop_front().or_else(|| rx.try_recv().ok())
                } else if retries
                    .front()
                    .is_some_and(|job: &RetirementJob| job.not_before <= now)
                {
                    retries.pop_front()
                } else {
                    rx.try_recv().ok()
                };
                if let Some(job) = job.take() {
                    stats.queue_depth.fetch_sub(1, Ordering::Relaxed);
                    stats.active.fetch_add(1, Ordering::Relaxed);
                    stats.record_queue();
                    let store = Arc::clone(&store);
                    let candidate = job.candidate.clone();
                    let durability = job.durability;
                    let prepared = job.prepared;
                    let handle = active.spawn(async move {
                        retire_one(store, &candidate, durability, prepared).await
                    });
                    active_jobs.insert(handle.id(), job);
                }
            }
        }
    }
}

struct RetirementAttempt {
    outcome: CoordinatedOutcome,
    cascade: Option<ExpiryCandidate>,
}

async fn retire_one(
    store: Arc<Store>,
    candidate: &ExpiryCandidate,
    durability: RetirementDurability,
    already_prepared: bool,
) -> io::Result<RetirementAttempt> {
    if !already_prepared {
        let prepared = match durability {
            RetirementDurability::Expiry => {
                store
                    .prepare_expiry_retirement(candidate, SystemTime::now())
                    .await
            }
            RetirementDurability::Explicit => store.prepare_delete(&candidate.stream()).await,
        };
        let terminal = match prepared {
            PrepareRetirement::Ready => None,
            PrepareRetirement::Renewed => Some(CoordinatedOutcome::Renewed),
            PrepareRetirement::Stale => Some(CoordinatedOutcome::Stale),
            PrepareRetirement::Gone => Some(CoordinatedOutcome::Gone),
        };
        if let Some(outcome) = terminal {
            candidate.clear_queued();
            return Ok(RetirementAttempt {
                outcome,
                cascade: None,
            });
        }

        #[cfg(target_os = "linux")]
        crate::sse_reactor::wake_stream(&candidate.stream());

        let stream = candidate.stream();
        store
            .subscriptions
            .clone()
            .on_stream_deleted(store.clone(), &stream.path, candidate.stream_id())
            .await?;
    }

    let cleanup_started = Instant::now();
    let step = store.finish_retirement(candidate, durability).await?;
    #[cfg(test)]
    pause_after_retirement_finish(candidate).await;
    crate::telemetry::record_expiry_cleanup(cleanup_started.elapsed().as_secs_f64());
    crate::telemetry::record_expiry_reclaimed_local_bytes(step.reclaimed_local_bytes);
    Ok(RetirementAttempt {
        outcome: CoordinatedOutcome::Retired(step.outcome),
        cascade: step.cascade,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{write_meta_sync, CreateResult, StreamConfig};
    use crate::tier::TierConfig;
    use std::time::UNIX_EPOCH;

    fn delete_config() -> Config {
        Config {
            mode: Mode::Delete,
            startup_grace: Duration::from_secs(60),
            bulk_fraction: 0.5,
            ..Config::default()
        }
    }

    #[test]
    fn delete_requires_startup_grace_and_a_complete_observe_pass() {
        let mut gate = DeleteGate::new(delete_config(), Duration::from_secs(10));
        assert!(!gate.observe_page(Duration::from_secs(20), 2, 0, true));
        assert!(!gate.observe_page(Duration::from_secs(60), 4, 1, true));
        assert!(gate.observe_page(Duration::from_secs(70), 4, 1, false));
    }

    #[test]
    fn bulk_pause_has_an_absolute_floor_is_sticky_and_one_is_the_override() {
        let mut guarded = DeleteGate::new(delete_config(), Duration::ZERO);
        assert!(!guarded.observe_page(Duration::from_secs(61), 8, 3, true));
        assert_eq!(guarded.pause(), None, "small populations do not latch");
        assert!(!guarded.observe_page(Duration::from_secs(62), 100, 65, true));
        assert_eq!(guarded.pause(), Some(PauseReason::Bulk));
        assert!(!guarded.observe_page(Duration::from_secs(63), 100, 0, true));

        let mut override_config = delete_config();
        override_config.bulk_fraction = 1.0;
        let mut overridden = DeleteGate::new(override_config, Duration::ZERO);
        assert!(!overridden.observe_page(Duration::from_secs(61), 1, 1, true));
        assert!(overridden.observe_page(Duration::from_secs(62), 1, 1, false));
        assert_eq!(overridden.pause(), None);
    }

    #[test]
    fn clock_guard_detects_forward_and_backward_wall_jumps_but_not_the_boundary() {
        let threshold = Duration::from_secs(5);
        for jumped_wall in [
            UNIX_EPOCH + Duration::from_secs(116),
            UNIX_EPOCH + Duration::from_secs(104),
        ] {
            let mut guard = ClockGuard::new(threshold);
            assert!(!guard.observe(UNIX_EPOCH + Duration::from_secs(100), Duration::ZERO));
            assert!(guard.observe(jumped_wall, Duration::from_secs(10)));
            assert!(guard.observe(
                UNIX_EPOCH + Duration::from_secs(110),
                Duration::from_secs(20)
            ));
        }

        let mut exact = ClockGuard::new(threshold);
        assert!(!exact.observe(UNIX_EPOCH + Duration::from_secs(100), Duration::ZERO));
        assert!(!exact.observe(
            UNIX_EPOCH + Duration::from_secs(115),
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn queue_holds_exactly_one_second_of_delete_admission() {
        let mut config = delete_config();
        config.delete_rate = 100;
        config.delete_concurrency = 4;
        assert_eq!(delete_queue_capacity(&config), 100);
        config.delete_rate = 2;
        config.delete_concurrency = 4;
        assert_eq!(delete_queue_capacity(&config), 4);
    }

    #[test]
    fn failed_channel_send_rolls_back_prepublished_queue_depth() {
        let config = delete_config();
        let stats = Stats::new(config.mode, 1);
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        assert_eq!(try_send_counted(&tx, &stats, 7), Err(7));
        assert_eq!(stats.queue_depth.load(Ordering::Relaxed), 0);
    }

    fn registry_test_candidate(tag: &str) -> (tempfile::TempDir, ExpiryCandidate) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new_with_tier(dir.path().to_path_buf(), TierConfig::default()).unwrap();
        let stream = match store
            .create(
                tag,
                StreamConfig {
                    content_type: "application/octet-stream".into(),
                    ttl_seconds: None,
                    expires_at: Some(UNIX_EPOCH),
                    expires_at_raw: Some("test-time".into()),
                    create_closed: false,
                    forked_from: None,
                    fork_offset_raw: None,
                    fork_sub_offset: None,
                },
                None,
                0,
            )
            .unwrap()
        {
            CreateResult::Created(stream) => stream,
            _ => panic!("registry test stream was not created"),
        };
        let candidate = store.candidate_for(&stream);
        (dir, candidate)
    }

    #[tokio::test]
    async fn exact_already_queued_join_survives_pre_send_and_completion_races() {
        let (_dir, candidate) = registry_test_candidate("join-success");
        let registry = Arc::new(RetirementRegistry::default());
        let (owned_tx, owned_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let first_registry = Arc::clone(&registry);
        let first_candidate = candidate.clone();
        let first = tokio::spawn(async move {
            let record = match first_registry
                .register(&first_candidate, RetirementDurability::Expiry, false)
                .unwrap()
            {
                RetirementRegistration::New { record, .. } => record,
                RetirementRegistration::Joined(_) => panic!("first admission unexpectedly joined"),
            };
            // This is the CAS-owned -> ordinary job-send window. The shared
            // registry entry must already be visible before this task proceeds.
            assert!(owned_tx.send(Arc::clone(&record)).is_ok());
            release_rx.await.unwrap();
            first_candidate.clear_queued();
            first_registry.publish(
                &record,
                &Ok(CoordinatedOutcome::Retired(RetirementOutcome::Reaped)),
                true,
            );
        });
        let record = owned_rx.await.unwrap();
        assert!(matches!(
            registry.register(&candidate, RetirementDurability::Explicit, true),
            Err(EnqueueError::AlreadyQueued)
        ));
        let joined = match registry
            .register(&candidate, RetirementDurability::Expiry, true)
            .unwrap()
        {
            RetirementRegistration::Joined(wait) => wait,
            RetirementRegistration::New { .. } => panic!("exact candidate was admitted twice"),
        };
        release_tx.send(()).unwrap();
        first.await.unwrap();

        assert_eq!(
            wait_for_retirement(joined, Duration::from_millis(100))
                .await
                .unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
        // A receiver attached after publication still sees the sticky terminal
        // result even though the registry entry has already been removed.
        assert_eq!(
            wait_for_retirement(record.subscribe(), Duration::from_millis(100))
                .await
                .unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
    }

    #[tokio::test]
    async fn joined_wait_is_woken_on_admission_failure_and_bounds_retry_wait() {
        let (_dir, candidate) = registry_test_candidate("join-bounds");
        let registry = RetirementRegistry::default();
        let record = match registry
            .register(&candidate, RetirementDurability::Expiry, false)
            .unwrap()
        {
            RetirementRegistration::New { record, .. } => record,
            RetirementRegistration::Joined(_) => panic!("first admission unexpectedly joined"),
        };
        let joined = match registry
            .register(&candidate, RetirementDurability::Expiry, true)
            .unwrap()
        {
            RetirementRegistration::Joined(wait) => wait,
            RetirementRegistration::New { .. } => panic!("exact candidate was admitted twice"),
        };
        registry.cancel_admission(
            &record,
            &io::Error::new(io::ErrorKind::WouldBlock, "injected admission failure"),
        );
        let failure = wait_for_retirement(joined, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::WouldBlock);
        assert!(failure.to_string().contains("injected admission failure"));

        let record = match registry
            .register(&candidate, RetirementDurability::Expiry, false)
            .unwrap()
        {
            RetirementRegistration::New { record, .. } => record,
            RetirementRegistration::Joined(_) => panic!("retry admission unexpectedly joined"),
        };
        registry.publish(
            &record,
            &Err(io::Error::other("injected retryable cleanup failure")),
            false,
        );
        let joined_retry = match registry
            .register(&candidate, RetirementDurability::Expiry, true)
            .unwrap()
        {
            RetirementRegistration::Joined(wait) => wait,
            RetirementRegistration::New { .. } => panic!("retry candidate was admitted twice"),
        };
        let timeout = wait_for_retirement(joined_retry, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(timeout.kind(), io::ErrorKind::WouldBlock);
        assert!(timeout.to_string().contains("timed out"));
        candidate.clear_queued();
        registry.publish(&record, &Err(io::Error::other("test cleanup")), true);
    }

    #[tokio::test]
    async fn exact_parent_waiter_joins_an_actively_owned_cascade() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new_with_tier(dir.path().to_path_buf(), TierConfig::default()).unwrap(),
        );
        let make_candidate = |path: &str| {
            let stream = match store
                .create(
                    path,
                    StreamConfig {
                        content_type: "application/octet-stream".into(),
                        ttl_seconds: None,
                        expires_at: Some(UNIX_EPOCH),
                        expires_at_raw: Some("test-time".into()),
                        create_closed: false,
                        forked_from: None,
                        fork_offset_raw: None,
                        fork_sub_offset: None,
                    },
                    None,
                    0,
                )
                .unwrap()
            {
                CreateResult::Created(stream) => stream,
                _ => panic!("cascade registry stream was not created"),
            };
            store.candidate_for(&stream)
        };
        let child = make_candidate("cascade-registry-child");
        let parent = make_candidate("cascade-registry-parent");
        let grandparent = make_candidate("cascade-registry-grandparent");
        let registry = Arc::new(RetirementRegistry::default());
        let (record, child_wait) = match registry
            .register(&child, RetirementDurability::Expiry, false)
            .unwrap()
        {
            RetirementRegistration::New { record, wait } => (record, wait),
            RetirementRegistration::Joined(_) => panic!("initial child unexpectedly joined"),
        };

        let (owned_tx, owned_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let owner_registry = Arc::clone(&registry);
        let owner_record = Arc::clone(&record);
        let owner_parent = parent.clone();
        let owner_grandparent = grandparent.clone();
        let owner_child = child.clone();
        let owner_store = Arc::clone(&store);
        let owner = tokio::spawn(async move {
            assert!(owner_registry.register_cascade(&owner_store, &owner_record, &owner_parent));
            assert!(owner_registry.register_cascade(
                &owner_store,
                &owner_record,
                &owner_grandparent
            ));
            owned_tx.send(()).unwrap();
            release_rx.await.unwrap();
            owner_child.clear_queued();
            owner_parent.clear_queued();
            owner_grandparent.clear_queued();
            owner_registry.publish(
                &owner_record,
                &Ok(CoordinatedOutcome::Retired(RetirementOutcome::Reaped)),
                true,
            );
        });

        owned_rx.await.unwrap();
        assert!(matches!(
            registry.register(&parent, RetirementDurability::Explicit, true),
            Err(EnqueueError::AlreadyQueued)
        ));
        let joined = match registry
            .register(&parent, RetirementDurability::Expiry, true)
            .expect("an active parent cascade must be exactly joinable")
        {
            RetirementRegistration::Joined(wait) => wait,
            RetirementRegistration::New { .. } => panic!("cascade parent was admitted twice"),
        };
        let grandparent_joined = match registry
            .register(&grandparent, RetirementDurability::Expiry, true)
            .expect("every active cascade generation must be exactly joinable")
        {
            RetirementRegistration::Joined(wait) => wait,
            RetirementRegistration::New { .. } => {
                panic!("cascade grandparent was admitted twice")
            }
        };
        release_tx.send(()).unwrap();
        owner.await.unwrap();
        for wait in [child_wait, joined, grandparent_joined] {
            assert_eq!(
                wait_for_retirement(wait, Duration::from_millis(100))
                    .await
                    .unwrap(),
                CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
            );
        }
        assert!(
            registry
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "terminal publication removes every exact generation row"
        );

        let cancelled = match registry
            .register(&child, RetirementDurability::Expiry, false)
            .unwrap()
        {
            RetirementRegistration::New { record, .. } => record,
            RetirementRegistration::Joined(_) => panic!("cancel cycle unexpectedly joined"),
        };
        assert!(registry.register_cascade(&store, &cancelled, &parent));
        assert!(registry.register_cascade(&store, &cancelled, &grandparent));
        registry.cancel_admission(
            &cancelled,
            &io::Error::new(io::ErrorKind::WouldBlock, "injected cascade cancellation"),
        );
        assert!(
            registry
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "admission cancellation removes every exact generation row"
        );
        for candidate in [&child, &parent, &grandparent] {
            assert!(
                candidate.try_mark_queued(),
                "admission cancellation clears every generation marker"
            );
            candidate.clear_queued();
        }

        let failed = match registry
            .register(&child, RetirementDurability::Expiry, false)
            .unwrap()
        {
            RetirementRegistration::New { record, .. } => record,
            RetirementRegistration::Joined(_) => panic!("fail-all cycle unexpectedly joined"),
        };
        assert!(registry.register_cascade(&store, &failed, &parent));
        assert!(registry.register_cascade(&store, &failed, &grandparent));
        registry.fail_all("injected coordinator stop");
        assert!(
            registry
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "coordinator failure removes every exact generation row"
        );
        for candidate in [&child, &parent, &grandparent] {
            assert!(
                candidate.try_mark_queued(),
                "coordinator failure clears every generation marker"
            );
            candidate.clear_queued();
        }
    }

    #[test]
    fn recovered_seed_requires_a_whole_pass_without_admission_loss() {
        let mut state = ScannerState::new(delete_config());
        let stats = Stats::new(Mode::Off, 1);
        let (tx, mut rx) = mpsc::channel(1);
        assert_eq!(try_send_counted(&tx, &stats, 1), Ok(()));
        let admitted_second = try_send_counted(&tx, &stats, 2).is_ok();
        assert!(!admitted_second, "the test saturated bounded admission");
        state.record_recovered_page(false, admitted_second, false);
        assert_eq!(rx.try_recv(), Ok(1));
        stats.queue_depth.fetch_sub(1, Ordering::Relaxed);
        state.record_recovered_page(true, true, false);
        assert!(
            !state.recovered_complete,
            "a later page cannot hide an earlier full queue"
        );
        state.record_recovered_page(false, true, false);
        state.record_recovered_page(true, true, false);
        assert!(
            state.recovered_complete,
            "a lossless full pass transfers retry ownership to the coordinator"
        );
    }

    #[test]
    fn permanently_failing_recovered_retirement_does_not_starve_live_expiry() {
        const CHILD: &str = "DS_TEST_RECOVERED_RETIREMENT_FAIRNESS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // The production coordinator is deliberately process-global. Keep
            // this end-to-end scanner/dispatcher regression isolated from the
            // coordinator-free unit tests in the parent test process.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "expiry_reaper::tests::permanently_failing_recovered_retirement_does_not_starve_live_expiry",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child recovery fairness regression failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let dir = std::env::temp_dir().join(format!(
                    "ds-expiry-recovered-fairness-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                let _ = std::fs::remove_dir_all(&dir);
                {
                    let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
                    let tombstone = match store
                        .create(
                            "recovered-stuck",
                            StreamConfig {
                                content_type: "application/octet-stream".into(),
                                ttl_seconds: None,
                                expires_at: None,
                                expires_at_raw: None,
                                create_closed: false,
                                forked_from: None,
                                fork_offset_raw: None,
                                fork_sub_offset: None,
                            },
                            None,
                            0,
                        )
                        .unwrap()
                    {
                        CreateResult::Created(stream) => stream,
                        _ => panic!("recovered test tombstone was not created"),
                    };
                    tombstone.shared.write().unwrap().soft_deleted = true;
                    write_meta_sync(&tombstone, true).unwrap();
                    assert!(matches!(
                        store
                            .create(
                                "live-due",
                                StreamConfig {
                                    content_type: "application/octet-stream".into(),
                                    ttl_seconds: None,
                                    expires_at: Some(UNIX_EPOCH),
                                    expires_at_raw: Some("test-time".into()),
                                    create_closed: false,
                                    forked_from: None,
                                    fork_offset_raw: None,
                                    fork_sub_offset: None,
                                },
                                None,
                                0,
                            )
                            .unwrap(),
                        CreateResult::Created(_)
                    ));
                }

                let store =
                    Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
                assert_eq!(store.recovered_retirement_count(), 1);
                assert_eq!(store.expiring_stream_count(), 1);

                // Turn the recovered tombstone's data path into a directory.
                // Its hard-retirement attempt will now fail permanently at
                // unlink while remaining indexed through retry/quarantine.
                let stuck_path = store
                    .streams
                    .get("recovered-stuck")
                    .unwrap()
                    .file_path
                    .clone();
                std::fs::remove_file(&stuck_path).unwrap();
                std::fs::create_dir(&stuck_path).unwrap();

                let config = Config {
                    mode: Mode::Delete,
                    scan_rate: 1,
                    delete_rate: 100_000,
                    delete_concurrency: 1,
                    startup_grace: Duration::ZERO,
                    bulk_fraction: 1.0,
                    ..Config::default()
                };
                let reaper = spawn(Arc::clone(&store), config);
                tokio::time::timeout(Duration::from_secs(6), async {
                    loop {
                        if !store.streams.contains_key("live-due") {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("recovered retry ownership starved ordinary live expiry");

                assert!(
                    store.streams.contains_key("recovered-stuck"),
                    "the injected permanent failure must remain outstanding"
                );
                assert_eq!(store.recovered_retirement_count(), 1);
                assert!(status().unwrap().failures > 0);
                reaper.shutdown().await;
                let _ = std::fs::remove_dir_all(dir);
            });
    }

    #[tokio::test]
    async fn scanner_supervisor_preserves_startup_bulk_and_clock_state_after_a_panic() {
        let dir = std::env::temp_dir().join(format!(
            "ds-expiry-supervisor-{}-{}",
            std::process::id(),
            unix_seconds()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let config = Config {
            mode: Mode::Observe,
            ..Config::default()
        };
        let stats = Arc::new(Stats::new(config.mode, delete_queue_capacity(&config)));
        let state = Arc::new(Mutex::new(ScannerState::new(delete_config())));
        let original_started = state.lock().unwrap().started;
        {
            let mut state = state.lock().unwrap();
            assert!(!state.gate.observe_page(
                Duration::from_secs(61),
                100,
                MIN_BULK_DUE_COUNT + 1,
                true,
            ));
            state.clock = ClockGuard::new(Duration::from_secs(5));
            assert!(!state
                .clock
                .observe(UNIX_EPOCH + Duration::from_secs(100), Duration::ZERO,));
            assert!(state.clock.observe(
                UNIX_EPOCH + Duration::from_secs(120),
                Duration::from_secs(10),
            ));
        }
        let (stop, stop_rx) = watch::channel(false);
        PANIC_SCANNER_ONCE.store(true, Ordering::Release);
        let supervisor = tokio::spawn(supervise_scanner(
            store,
            config,
            stop_rx,
            stats.clone(),
            Arc::clone(&state),
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            while stats.scanner_restarts.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("scanner generation was not restarted");

        {
            let state = state.lock().unwrap();
            assert_eq!(state.started, original_started, "startup baseline survived");
            assert_eq!(state.gate.pause(), Some(PauseReason::Bulk));
            assert!(state.clock.paused, "clock latch survived");
        }

        let _ = stop.send(true);
        tokio::time::timeout(Duration::from_secs(2), supervisor)
            .await
            .expect("scanner supervisor did not stop")
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn graceful_shutdown_drains_a_job_buffered_behind_active_work() {
        let dir = std::env::temp_dir().join(format!(
            "ds-expiry-drain-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let stream_config = || StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: Some(UNIX_EPOCH),
            expires_at_raw: Some("test-time".into()),
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let mut candidates = Vec::new();
        for path in ["buffered-a", "buffered-b"] {
            let stream = match store.create(path, stream_config(), None, 0).unwrap() {
                CreateResult::Created(stream) => stream,
                _ => panic!("test stream was not created"),
            };
            let candidate = store.candidate_for(&stream);
            assert!(candidate.try_mark_queued());
            candidates.push(candidate);
        }

        let mut config = delete_config();
        config.delete_rate = 1_000;
        config.delete_concurrency = 1;
        let capacity = 2;
        let admission = Arc::new(Semaphore::new(capacity));
        let (tx, rx) = mpsc::channel(capacity);
        let stats = Arc::new(Stats::new(config.mode, capacity));
        let mut completions = Vec::new();
        for candidate in candidates {
            let (completion, completed) = oneshot::channel();
            let permit = Arc::clone(&admission).try_acquire_owned().unwrap();
            tx.try_send(RetirementJob {
                candidate,
                durability: RetirementDurability::Expiry,
                prepared: false,
                attempt: 0,
                not_before: Instant::now(),
                completion: Some(completion),
                retirement: None,
                _admission: permit,
            })
            .unwrap();
            stats.queue_depth.fetch_add(1, Ordering::Relaxed);
            completions.push(completed);
        }
        drop(tx);
        let (stop, stop_rx) = watch::channel(false);
        let dispatcher = tokio::spawn(dispatch_loop(
            Arc::clone(&store),
            config,
            rx,
            stop_rx,
            Arc::clone(&stats),
            None,
        ));
        stop.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(3), async {
            for completed in completions {
                assert_eq!(
                    completed.await.unwrap().unwrap(),
                    CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
                );
            }
            dispatcher.await.unwrap();
        })
        .await
        .expect("dispatcher starved a buffered job while draining");
        assert_eq!(stats.queue_depth.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn exhausted_retry_budget_releases_admission_for_unrelated_retirement() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new_with_tier(dir.path().to_path_buf(), TierConfig::default()).unwrap(),
        );
        let stream_config = || StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: Some(UNIX_EPOCH),
            expires_at_raw: Some("test-time".into()),
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let create_candidate = |path| {
            let stream = match store.create(path, stream_config(), None, 0).unwrap() {
                CreateResult::Created(stream) => stream,
                _ => panic!("retry-budget test stream was not created"),
            };
            store.candidate_for(&stream)
        };
        let stuck = create_candidate("retry-stuck");
        let stuck_probe = stuck.clone();
        let unrelated = create_candidate("retry-unrelated");
        assert!(stuck.try_mark_queued());
        let stuck_path = stuck.stream().file_path.clone();
        std::fs::remove_file(&stuck_path).unwrap();
        std::fs::create_dir(&stuck_path).unwrap();

        let mut config = delete_config();
        config.delete_rate = 100_000;
        config.delete_concurrency = 1;
        let admission = Arc::new(Semaphore::new(1));
        let stuck_permit = Arc::clone(&admission).try_acquire_owned().unwrap();
        let (tx, rx) = mpsc::channel(1);
        let stats = Arc::new(Stats::new(config.mode, 1));
        tx.try_send(RetirementJob {
            candidate: stuck,
            durability: RetirementDurability::Expiry,
            prepared: false,
            // Make the deterministic next failure exhaust the finite policy;
            // the test does not wait through production backoff intervals.
            attempt: MAX_RETIREMENT_ATTEMPTS - 1,
            not_before: Instant::now(),
            completion: None,
            retirement: None,
            _admission: stuck_permit,
        })
        .unwrap();
        stats.queue_depth.store(1, Ordering::Relaxed);
        let (stop, stop_rx) = watch::channel(false);
        let dispatcher = tokio::spawn(dispatch_loop(
            Arc::clone(&store),
            config,
            rx,
            stop_rx,
            Arc::clone(&stats),
            None,
        ));

        let unrelated_permit = tokio::time::timeout(
            Duration::from_millis(250),
            Arc::clone(&admission).acquire_owned(),
        )
        .await
        .expect("persistent failure permanently exhausted bounded admission")
        .unwrap();
        assert!(unrelated.try_mark_queued());
        let (completion, completed) = oneshot::channel();
        tx.try_send(RetirementJob {
            candidate: unrelated,
            durability: RetirementDurability::Expiry,
            prepared: false,
            attempt: 0,
            not_before: Instant::now(),
            completion: Some(completion),
            retirement: None,
            _admission: unrelated_permit,
        })
        .unwrap();
        stats.queue_depth.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), completed)
                .await
                .expect("unrelated retirement remained wedged")
                .unwrap()
                .unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
        assert_eq!(stats.quarantined_retirements.load(Ordering::Relaxed), 1);
        assert!(
            !stuck_probe.try_mark_queued(),
            "quarantine marker must prevent hot scanner re-admission"
        );

        drop(tx);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), dispatcher)
            .await
            .expect("dispatcher did not stop after retry quarantine")
            .unwrap();
        assert_eq!(admission.available_permits(), 1);
    }

    async fn marked_cascade_fixture(
        tag: &str,
    ) -> (
        tempfile::TempDir,
        Arc<Store>,
        ExpiryCandidate,
        ExpiryCandidate,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new_with_tier(dir.path().to_path_buf(), TierConfig::default()).unwrap(),
        );
        let config = |forked_from: Option<&str>| StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: forked_from.map(str::to_owned),
            fork_offset_raw: forked_from.map(|_| "0".into()),
            fork_sub_offset: None,
        };
        let parent_path = format!("{tag}-parent");
        let child_path = format!("{tag}-child");
        let parent = match store.create(&parent_path, config(None), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("cascade parent was not created"),
        };
        let child = match store
            .create(
                &child_path,
                config(Some(&parent_path)),
                Some(Arc::clone(&parent)),
                0,
            )
            .unwrap()
        {
            CreateResult::Created(stream) => stream,
            _ => panic!("cascade child was not created"),
        };
        assert_eq!(
            store.prepare_delete(&parent).await,
            PrepareRetirement::Ready
        );
        assert_eq!(
            store
                .finish_retirement(
                    &store.candidate_for(&parent),
                    RetirementDurability::Explicit,
                )
                .await
                .unwrap()
                .outcome,
            RetirementOutcome::SoftDeleted
        );

        let parent_candidate = store.candidate_for(&parent);
        assert!(
            parent_candidate.try_mark_queued(),
            "fixture reserves the exact parent for an existing owner/quarantine"
        );
        let child_candidate = store.candidate_for(&child);
        assert!(child_candidate.try_mark_queued());
        (dir, store, child_candidate, parent_candidate)
    }

    #[tokio::test]
    async fn marked_cascade_parent_transfers_ownership_and_releases_capacity() {
        let (_dir, store, child, marked_parent) =
            marked_cascade_fixture("cascade-conflict-capacity").await;
        let mut config = delete_config();
        config.delete_rate = 100_000;
        config.delete_concurrency = 1;
        let admission = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&admission).try_acquire_owned().unwrap();
        let (tx, rx) = mpsc::channel(1);
        let (completion, completed) = oneshot::channel();
        tx.try_send(RetirementJob {
            candidate: child,
            durability: RetirementDurability::Explicit,
            prepared: false,
            attempt: 0,
            not_before: Instant::now(),
            completion: Some(completion),
            retirement: None,
            _admission: permit,
        })
        .unwrap();
        let stats = Arc::new(Stats::new(config.mode, 1));
        stats.queue_depth.store(1, Ordering::Relaxed);
        let (stop, stop_rx) = watch::channel(false);
        let dispatcher = tokio::spawn(dispatch_loop(
            Arc::clone(&store),
            config,
            rx,
            stop_rx,
            Arc::clone(&stats),
            None,
        ));

        // Permit release follows real durable unlink and directory fsync work.
        // Keep a finite watchdog for permanent retention without making normal
        // suite-wide I/O contention look like a lifecycle failure.
        let released = tokio::time::timeout(
            Duration::from_secs(3),
            Arc::clone(&admission).acquire_owned(),
        )
        .await;
        let permit = match released {
            Ok(Ok(permit)) => permit,
            other => {
                dispatcher.abort();
                panic!("marked cascade parent retained bounded capacity: {other:?}");
            }
        };
        drop(permit);
        assert_eq!(
            completed.await.unwrap().unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
        assert!(
            !marked_parent.try_mark_queued(),
            "ownership transfer must preserve the existing exact marker"
        );

        drop(tx);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), dispatcher)
            .await
            .expect("dispatcher did not stop after ownership transfer")
            .unwrap();
        assert_eq!(stats.queue_depth.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn shutdown_does_not_requeue_a_marked_cascade_parent_forever() {
        let (_dir, store, child, marked_parent) =
            marked_cascade_fixture("cascade-conflict-drain").await;
        let mut config = delete_config();
        config.delete_rate = 100_000;
        config.delete_concurrency = 1;
        let admission = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&admission).try_acquire_owned().unwrap();
        let (tx, rx) = mpsc::channel(1);
        let (completion, completed) = oneshot::channel();
        tx.try_send(RetirementJob {
            candidate: child,
            durability: RetirementDurability::Explicit,
            prepared: false,
            attempt: 0,
            not_before: Instant::now(),
            completion: Some(completion),
            retirement: None,
            _admission: permit,
        })
        .unwrap();
        drop(tx);
        let stats = Arc::new(Stats::new(config.mode, 1));
        stats.queue_depth.store(1, Ordering::Relaxed);
        let (stop, stop_rx) = watch::channel(false);
        let dispatcher = tokio::spawn(dispatch_loop(
            Arc::clone(&store),
            config,
            rx,
            stop_rx,
            Arc::clone(&stats),
            None,
        ));
        stop.send(true).unwrap();

        // This watchdog distinguishes a finite drain from the historical
        // permanent marker-requeue loop. The path performs real durable file
        // and directory fsyncs, so it must tolerate suite-wide I/O contention.
        let drained = tokio::time::timeout(Duration::from_secs(3), async {
            let outcome = completed.await.unwrap().unwrap();
            dispatcher.await.unwrap();
            outcome
        })
        .await;
        assert_eq!(
            drained.expect("marked cascade continuation hung shutdown"),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
        assert!(
            !marked_parent.try_mark_queued(),
            "drain must not clear another owner's exact marker"
        );
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(stats.queue_depth.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn concurrent_parent_soft_delete_and_last_child_reap_cannot_lose_parent_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new_with_tier(dir.path().to_path_buf(), TierConfig::default()).unwrap(),
        );
        let stream_config = |forked_from: Option<&str>| StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: forked_from.map(str::to_owned),
            fork_offset_raw: forked_from.map(|_| "0".into()),
            fork_sub_offset: None,
        };
        let parent_path = "soft-owner-race-parent";
        let child_path = "soft-owner-race-child";
        let parent = match store
            .create(parent_path, stream_config(None), None, 0)
            .unwrap()
        {
            CreateResult::Created(stream) => stream,
            _ => panic!("parent was not created"),
        };
        let child = match store
            .create(
                child_path,
                stream_config(Some(parent_path)),
                Some(Arc::clone(&parent)),
                0,
            )
            .unwrap()
        {
            CreateResult::Created(stream) => stream,
            _ => panic!("child was not created"),
        };

        let parent_candidate = store.candidate_for(&parent);
        let child_candidate = store.candidate_for(&child);
        let retirements = Arc::new(RetirementRegistry::default());
        let (parent_record, parent_wait) = match retirements
            .register(&parent_candidate, RetirementDurability::Explicit, false)
            .unwrap()
        {
            RetirementRegistration::New { record, wait } => (record, wait),
            RetirementRegistration::Joined(_) => panic!("parent unexpectedly joined"),
        };
        let (child_record, child_wait) = match retirements
            .register(&child_candidate, RetirementDurability::Explicit, false)
            .unwrap()
        {
            RetirementRegistration::New { record, wait } => (record, wait),
            RetirementRegistration::Joined(_) => panic!("child unexpectedly joined"),
        };

        let mut config = delete_config();
        config.delete_rate = 100_000;
        config.delete_concurrency = 2;
        let admission = Arc::new(Semaphore::new(2));
        let (tx, rx) = mpsc::channel(2);
        let stats = Arc::new(Stats::new(config.mode, 2));
        let (parent_completion, parent_completed) = oneshot::channel();
        tx.try_send(RetirementJob {
            candidate: parent_candidate,
            durability: RetirementDurability::Explicit,
            prepared: false,
            attempt: 0,
            not_before: Instant::now(),
            completion: Some(parent_completion),
            retirement: Some(parent_record),
            _admission: Arc::clone(&admission).try_acquire_owned().unwrap(),
        })
        .unwrap();
        stats.queue_depth.store(1, Ordering::Relaxed);

        let hook = install_retire_after_finish_hook(parent_path);
        let (stop, stop_rx) = watch::channel(false);
        let dispatcher = tokio::spawn(dispatch_loop(
            Arc::clone(&store),
            config,
            rx,
            stop_rx,
            Arc::clone(&stats),
            Some(Arc::clone(&retirements)),
        ));
        tokio::time::timeout(Duration::from_secs(2), hook.reached())
            .await
            .expect("parent did not finish its physical soft delete");

        let (child_completion, child_completed) = oneshot::channel();
        tx.try_send(RetirementJob {
            candidate: child_candidate,
            durability: RetirementDurability::Explicit,
            prepared: false,
            attempt: 0,
            not_before: Instant::now(),
            completion: Some(child_completion),
            retirement: Some(child_record),
            _admission: Arc::clone(&admission).try_acquire_owned().unwrap(),
        })
        .unwrap();
        stats.queue_depth.fetch_add(1, Ordering::Relaxed);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), child_completed)
                .await
                .expect("child completion was not processed before parent publication")
                .unwrap()
                .unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
        assert_eq!(
            wait_for_retirement(child_wait, Duration::from_millis(100))
                .await
                .unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );

        hook.release();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), parent_completed)
                .await
                .expect("parent completion remained unresolved")
                .unwrap()
                .unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
        assert_eq!(
            wait_for_retirement(parent_wait, Duration::from_millis(100))
                .await
                .unwrap(),
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );

        assert!(store.get(parent_path).is_none(), "parent tombstone leaked");
        assert!(matches!(
            store
                .create(parent_path, stream_config(None), None, 0)
                .unwrap(),
            CreateResult::Created(_)
        ));
        drop(tx);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), dispatcher)
            .await
            .expect("dispatcher did not stop")
            .unwrap();
        assert_eq!(admission.available_permits(), 2);
    }

    #[tokio::test]
    async fn fork_cascade_keeps_one_admission_and_completion_until_every_step_finishes() {
        let dir = std::env::temp_dir().join(format!(
            "ds-expiry-cascade-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let config = |forked_from: Option<&str>| StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: forked_from.map(str::to_owned),
            fork_offset_raw: forked_from.map(|_| "0".into()),
            fork_sub_offset: None,
        };
        let parent = match store
            .create("cascade-parent", config(None), None, 0)
            .unwrap()
        {
            CreateResult::Created(stream) => stream,
            _ => panic!("parent was not created"),
        };
        let child = match store
            .create(
                "cascade-child",
                config(Some("cascade-parent")),
                Some(Arc::clone(&parent)),
                0,
            )
            .unwrap()
        {
            CreateResult::Created(stream) => stream,
            _ => panic!("child was not created"),
        };
        assert_eq!(
            store.prepare_delete(&parent).await,
            PrepareRetirement::Ready
        );
        assert_eq!(
            store
                .finish_retirement(
                    &store.candidate_for(&parent),
                    RetirementDurability::Explicit,
                )
                .await
                .unwrap()
                .outcome,
            RetirementOutcome::SoftDeleted
        );

        let candidate = store.candidate_for(&child);
        assert!(candidate.try_mark_queued());
        let mut reaper_config = delete_config();
        reaper_config.delete_rate = 1_000;
        reaper_config.delete_concurrency = 1;
        let admission = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&admission).try_acquire_owned().unwrap();
        let (tx, rx) = mpsc::channel(1);
        let (completion, completed) = oneshot::channel();
        tx.try_send(RetirementJob {
            candidate,
            durability: RetirementDurability::Explicit,
            prepared: false,
            attempt: 0,
            not_before: Instant::now(),
            completion: Some(completion),
            retirement: None,
            _admission: permit,
        })
        .unwrap();
        drop(tx);
        let stats = Arc::new(Stats::new(reaper_config.mode, 1));
        stats.queue_depth.store(1, Ordering::Relaxed);
        let (stop, stop_rx) = watch::channel(false);
        let dispatcher = tokio::spawn(dispatch_loop(
            Arc::clone(&store),
            reaper_config,
            rx,
            stop_rx,
            Arc::clone(&stats),
            None,
        ));
        stop.send(true).unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(3), completed)
            .await
            .expect("cascade did not finish")
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome,
            CoordinatedOutcome::Retired(RetirementOutcome::Reaped)
        );
        tokio::time::timeout(Duration::from_secs(3), dispatcher)
            .await
            .expect("dispatcher did not finish")
            .unwrap();
        assert!(store.get("cascade-child").is_none());
        assert!(store.get("cascade-parent").is_none());
        assert_eq!(stats.outcomes_reaped.load(Ordering::Relaxed), 2);
        assert_eq!(admission.available_permits(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
