//! Completion and admission state shared by the later retirement executor.

// TODO(retirement-C2): retry policy consumes the remaining failure fields.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::watch;

use super::coordinator::ExpiryFenceLease;

pub(crate) const DEFAULT_RETIREMENT_QUEUE_CAPACITY: usize = 4096;
pub(crate) const DEFAULT_RETIREMENT_CONCURRENCY: usize = 64;
pub(crate) const RESERVED_INTERACTIVE_COORDINATOR_PERMITS: usize = 8;
pub(crate) const DEFAULT_PROACTIVE_COORDINATOR_CONCURRENCY: usize =
    DEFAULT_RETIREMENT_CONCURRENCY - RESERVED_INTERACTIVE_COORDINATOR_PERMITS;
pub(crate) const DEFAULT_PHYSICAL_QUEUE_CAPACITY: usize = 1024;
pub(crate) const DEFAULT_INTERACTIVE_PHYSICAL_QUEUE_CAPACITY: usize = 64;
pub(crate) const DEFAULT_PROACTIVE_PHYSICAL_QUEUE_CAPACITY: usize =
    DEFAULT_PHYSICAL_QUEUE_CAPACITY - DEFAULT_INTERACTIVE_PHYSICAL_QUEUE_CAPACITY;
pub(crate) const DEFAULT_CLEANUP_WORKERS: usize = 4;
pub(crate) const RESERVED_INTERACTIVE_CLEANUP_WORKERS: usize = 1;
pub(crate) const DEFAULT_PROACTIVE_CLEANUP_WORKERS: usize =
    DEFAULT_CLEANUP_WORKERS - RESERVED_INTERACTIVE_CLEANUP_WORKERS;
pub(crate) const MAX_CLEANUP_ATTEMPTS: u8 = 10;
pub(crate) const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60);
pub(crate) const CLEANUP_FAILURE_COOLDOWN: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetirementPriority {
    Interactive,
    Proactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetirementAdmission {
    QueueFull,
    CoolingDown,
    ShuttingDown,
    IdentityConflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LogicalCompletion {
    Completed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FirstAttemptCompletion {
    Succeeded { reclaimed_local_bytes: u64 },
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TerminalCleanupCompletion {
    Succeeded { reclaimed_local_bytes: u64 },
    Failed,
    Cancelled,
}

/// Immutable bounded health projection for the retirement executor. It
/// intentionally contains no stream identity, path, ticket, or job handle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RetirementSnapshot {
    pub(crate) queue_capacity: usize,
    pub(crate) total_jobs: usize,
    pub(crate) interactive_pending: usize,
    pub(crate) proactive_pending: usize,
    pub(crate) active_interactive: usize,
    pub(crate) active_proactive: usize,
    pub(crate) coordinator_capacity: usize,
    pub(crate) proactive_coordinator_capacity: usize,
    pub(crate) interactive_physical_capacity: usize,
    pub(crate) proactive_physical_capacity: usize,
    pub(crate) physical_interactive_queued: usize,
    pub(crate) physical_proactive_queued: usize,
    pub(crate) physical_interactive_active: usize,
    pub(crate) physical_proactive_active: usize,
    pub(crate) cleanup_workers_total: usize,
    pub(crate) cleanup_workers_live: usize,
    pub(crate) retry_heap_count: usize,
    pub(crate) cumulative_retry_attempts: u64,
    pub(crate) terminal_cleanup_failed_current: u64,
    pub(crate) terminal_successes: u64,
    pub(crate) terminal_failures: u64,
    pub(crate) terminal_cancellations: u64,
    pub(crate) first_attempt_successes: u64,
    pub(crate) first_attempt_failures: u64,
    pub(crate) first_attempt_cancellations: u64,
    pub(crate) reclaimed_local_bytes: u64,
    pub(crate) latest_cleanup_wall_time: Option<SystemTime>,
    pub(crate) last_successful_cleanup_wall_time: Option<SystemTime>,
    pub(crate) latest_cleanup_duration: Option<Duration>,
    pub(crate) last_successful_cleanup_duration: Option<Duration>,
    pub(crate) oldest_admitted_age: Option<Duration>,
    pub(crate) closed: bool,
}

/// Fixed limits used by the future worker and coordinator modules.
#[derive(Clone, Debug)]
pub(crate) struct RetirementConfig {
    pub(crate) queue_capacity: usize,
    pub(crate) coordinator_capacity: usize,
    pub(crate) proactive_coordinator_capacity: usize,
    pub(crate) interactive_physical_capacity: usize,
    pub(crate) proactive_physical_capacity: usize,
    pub(crate) physical_queue_capacity: usize,
    pub(crate) cleanup_workers: usize,
    pub(crate) retry_base: Duration,
    pub(crate) cooldown: Duration,
}

impl Default for RetirementConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_RETIREMENT_QUEUE_CAPACITY,
            coordinator_capacity: DEFAULT_RETIREMENT_CONCURRENCY,
            proactive_coordinator_capacity: DEFAULT_PROACTIVE_COORDINATOR_CONCURRENCY,
            interactive_physical_capacity: DEFAULT_INTERACTIVE_PHYSICAL_QUEUE_CAPACITY,
            proactive_physical_capacity: DEFAULT_PROACTIVE_PHYSICAL_QUEUE_CAPACITY,
            physical_queue_capacity: DEFAULT_PHYSICAL_QUEUE_CAPACITY,
            cleanup_workers: DEFAULT_CLEANUP_WORKERS,
            retry_base: Duration::from_secs(1),
            cooldown: CLEANUP_FAILURE_COOLDOWN,
        }
    }
}

impl RetirementConfig {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.queue_capacity == 0 || self.coordinator_capacity == 0 {
            return Err("retirement capacities must be non-zero");
        }
        if self.coordinator_capacity < RESERVED_INTERACTIVE_COORDINATOR_PERMITS {
            return Err("coordination capacity must reserve eight interactive permits");
        }
        if self.proactive_coordinator_capacity
            > self.coordinator_capacity - RESERVED_INTERACTIVE_COORDINATOR_PERMITS
        {
            return Err("proactive coordination must preserve interactive permits");
        }
        if self.physical_queue_capacity == 0 {
            return Err("physical queue capacity must be non-zero");
        }
        if self.interactive_physical_capacity == 0 {
            return Err("physical queue must reserve interactive capacity");
        }
        if self.interactive_physical_capacity + self.proactive_physical_capacity
            != self.physical_queue_capacity
        {
            return Err("physical queue partition must total the configured capacity");
        }
        if self.cleanup_workers < RESERVED_INTERACTIVE_CLEANUP_WORKERS {
            return Err("cleanup workers must reserve one interactive worker");
        }
        Ok(())
    }
}

/// Exponential retry delay for a failed physical cleanup attempt. The shift is
/// bounded before multiplication so a malformed large attempt count cannot
/// overflow, and the approved sixty-second maximum remains authoritative.
pub(crate) fn retry_backoff(attempt: u8, base: Duration) -> Duration {
    let shift = u32::from(attempt.saturating_sub(1)).min(6);
    base.saturating_mul(1u32 << shift).min(MAX_RETRY_BACKOFF)
}

struct TicketState {
    logical: watch::Sender<Option<LogicalCompletion>>,
    first_attempt: watch::Sender<Option<FirstAttemptCompletion>>,
    terminal: watch::Sender<Option<TerminalCleanupCompletion>>,
}

/// A level-triggered observation handle shared by duplicate admissions.
#[derive(Clone)]
pub(crate) struct RetirementTicket {
    state: Arc<TicketState>,
}

impl RetirementTicket {
    pub(crate) fn new() -> Self {
        let (logical, _) = watch::channel(None);
        let (first_attempt, _) = watch::channel(None);
        let (terminal, _) = watch::channel(None);
        Self {
            state: Arc::new(TicketState {
                logical,
                first_attempt,
                terminal,
            }),
        }
    }

    pub(crate) fn complete_logical(&self, result: LogicalCompletion) {
        self.state.logical.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(result);
                true
            }
        });
    }

    pub(crate) fn complete_first_attempt(&self, result: FirstAttemptCompletion) {
        self.state.first_attempt.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(result);
                true
            }
        });
    }

    pub(crate) fn complete_terminal(&self, result: TerminalCleanupCompletion) {
        self.state.terminal.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(result);
                true
            }
        });
    }

    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    pub(crate) async fn wait_logical(&self) -> LogicalCompletion {
        wait_completion(&self.state.logical).await
    }

    pub(crate) async fn wait_first_attempt(&self) -> FirstAttemptCompletion {
        wait_completion(&self.state.first_attempt).await
    }

    pub(crate) async fn wait_terminal(&self) -> TerminalCleanupCompletion {
        wait_completion(&self.state.terminal).await
    }
}

async fn wait_completion<T: Clone>(sender: &watch::Sender<Option<T>>) -> T {
    // Register before inspecting the level value: a concurrent completion is
    // either already retained or wakes this receiver through `changed`.
    let mut receiver = sender.subscribe();
    loop {
        if let Some(value) = receiver.borrow().clone() {
            return value;
        }
        receiver
            .changed()
            .await
            .expect("retirement ticket sender lives with its ticket");
    }
}

/// Non-persisted state held by each StreamState. Recovery always creates this
/// afresh, so an old failure cannot impose a stale cooldown after restart.
#[derive(Default)]
pub(crate) struct RetirementState {
    ticket: Option<RetirementTicket>,
    attempts: u8,
    cleanup_failed_at: Option<SystemTime>,
    cooldown_until: Option<Instant>,
    expiry_fence_lease: Option<ExpiryFenceLease>,
}

pub(crate) enum RetirementReservation {
    New(RetirementTicket),
    Existing(RetirementTicket),
    CoolingDown,
}

impl RetirementState {
    pub(crate) fn install_expiry_fence_lease(
        &mut self,
        lease: ExpiryFenceLease,
    ) -> Option<ExpiryFenceLease> {
        self.expiry_fence_lease.replace(lease)
    }
    pub(crate) fn has_terminal_failure(&self) -> bool {
        self.cleanup_failed_at.is_some()
    }

    pub(crate) fn reserve(&mut self, now: Instant) -> RetirementReservation {
        if let Some(until) = self.cooldown_until {
            if now < until {
                return RetirementReservation::CoolingDown;
            }
            self.cooldown_until = None;
            self.cleanup_failed_at = None;
        }
        if let Some(ticket) = &self.ticket {
            return RetirementReservation::Existing(ticket.clone());
        }
        let ticket = RetirementTicket::new();
        self.ticket = Some(ticket.clone());
        self.attempts = 0;
        RetirementReservation::New(ticket)
    }

    pub(crate) fn record_attempt(&mut self) -> u8 {
        self.attempts = self.attempts.saturating_add(1);
        self.attempts
    }

    pub(crate) fn finish(&mut self, ticket: &RetirementTicket) -> bool {
        if !self.owns(ticket) {
            return false;
        }
        self.ticket = None;
        self.attempts = 0;
        self.cleanup_failed_at = None;
        self.cooldown_until = None;
        true
    }

    pub(crate) fn fail_terminal(
        &mut self,
        ticket: &RetirementTicket,
        now: Instant,
        wall_now: SystemTime,
        cooldown: Duration,
    ) -> bool {
        if !self.owns(ticket) {
            return false;
        }
        self.ticket = None;
        self.attempts = 0;
        self.cleanup_failed_at = Some(wall_now);
        self.cooldown_until = Some(now + cooldown);
        true
    }

    fn owns(&self, ticket: &RetirementTicket) -> bool {
        self.ticket
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.state, &ticket.state))
    }

    #[cfg(test)]
    pub(crate) fn is_clean(&self) -> bool {
        self.ticket.is_none()
            && self.attempts == 0
            && self.cleanup_failed_at.is_none()
            && self.cooldown_until.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Barrier;

    #[test]
    fn retirement_queue_ticket_defaults_and_config_are_pinned() {
        let config = RetirementConfig::default();
        assert_eq!(DEFAULT_RETIREMENT_QUEUE_CAPACITY, 4096);
        assert_eq!(DEFAULT_RETIREMENT_CONCURRENCY, 64);
        assert_eq!(RESERVED_INTERACTIVE_COORDINATOR_PERMITS, 8);
        assert_eq!(DEFAULT_PROACTIVE_COORDINATOR_CONCURRENCY, 56);
        assert_eq!(DEFAULT_INTERACTIVE_PHYSICAL_QUEUE_CAPACITY, 64);
        assert_eq!(DEFAULT_PROACTIVE_PHYSICAL_QUEUE_CAPACITY, 960);
        assert_eq!(DEFAULT_CLEANUP_WORKERS, 4);
        assert_eq!(DEFAULT_PROACTIVE_CLEANUP_WORKERS, 3);
        assert_eq!(MAX_CLEANUP_ATTEMPTS, 10);
        assert_eq!(MAX_RETRY_BACKOFF, Duration::from_secs(60));
        assert_eq!(CLEANUP_FAILURE_COOLDOWN, Duration::from_secs(5 * 60));
        assert!(config.validate().is_ok());

        let mut invalid = config.clone();
        invalid.queue_capacity = 0;
        assert!(invalid.validate().is_err());
        invalid = config.clone();
        invalid.coordinator_capacity = RESERVED_INTERACTIVE_COORDINATOR_PERMITS - 1;
        assert!(invalid.validate().is_err());
        invalid = config.clone();
        invalid.proactive_coordinator_capacity = DEFAULT_PROACTIVE_COORDINATOR_CONCURRENCY + 1;
        assert!(invalid.validate().is_err());
        invalid = config.clone();
        invalid.proactive_physical_capacity -= 1;
        assert!(invalid.validate().is_err());
        invalid = config.clone();
        invalid.physical_queue_capacity = 0;
        invalid.interactive_physical_capacity = 0;
        invalid.proactive_physical_capacity = 0;
        assert!(invalid.validate().is_err());
        invalid = config.clone();
        invalid.interactive_physical_capacity = 0;
        invalid.proactive_physical_capacity = 1024;
        assert!(invalid.validate().is_err());
        invalid = config;
        invalid.cleanup_workers = 0;
        assert!(invalid.validate().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_ticket_late_subscribers_observe_each_phase() {
        let ticket = RetirementTicket::new();
        ticket.complete_logical(LogicalCompletion::Completed);
        ticket.complete_first_attempt(FirstAttemptCompletion::Failed);
        ticket.complete_terminal(TerminalCleanupCompletion::Failed);
        assert_eq!(ticket.wait_logical().await, LogicalCompletion::Completed);
        assert_eq!(
            ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        assert_eq!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Failed
        );

        ticket.complete_logical(LogicalCompletion::Cancelled);
        ticket.complete_first_attempt(FirstAttemptCompletion::Cancelled);
        ticket.complete_terminal(TerminalCleanupCompletion::Cancelled);
        assert_eq!(ticket.wait_logical().await, LogicalCompletion::Completed);
        assert_eq!(
            ticket.wait_first_attempt().await,
            FirstAttemptCompletion::Failed
        );
        assert_eq!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Failed
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_queue_ticket_waiter_before_completion_wakes() {
        let ticket = RetirementTicket::new();
        let barrier = Arc::new(Barrier::new(2));
        let waiting_ticket = ticket.clone();
        let waiting_barrier = barrier.clone();
        let waiter = tokio::spawn(async move {
            let mut receiver = waiting_ticket.state.logical.subscribe();
            waiting_barrier.wait().await;
            receiver
                .changed()
                .await
                .expect("ticket sender remains live");
            let completed = receiver.borrow().clone();
            completed
        });
        barrier.wait().await;
        tokio::task::yield_now().await;
        ticket.complete_logical(LogicalCompletion::Completed);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("watch waiter should not hang")
                .expect("waiter task should not panic"),
            Some(LogicalCompletion::Completed)
        );
    }

    #[test]
    fn retirement_queue_state_deduplicates_and_clears() {
        let now = Instant::now();
        let mut state = RetirementState::default();
        let first = match state.reserve(now) {
            RetirementReservation::New(ticket) => ticket,
            _ => panic!("first reservation must allocate"),
        };
        let duplicate = match state.reserve(now) {
            RetirementReservation::Existing(ticket) => ticket,
            _ => panic!("duplicate reservation must share ticket"),
        };
        assert!(Arc::ptr_eq(&first.state, &duplicate.state));
        assert_eq!(state.record_attempt(), 1);
        assert!(state.finish(&first));
        assert!(state.is_clean());
    }

    #[test]
    fn retirement_queue_state_terminal_failure_enforces_cooldown() {
        let now = Instant::now();
        let mut state = RetirementState::default();
        let first = match state.reserve(now) {
            RetirementReservation::New(ticket) => ticket,
            _ => panic!("first reservation must allocate"),
        };
        assert!(state.fail_terminal(&first, now, SystemTime::now(), Duration::from_secs(5)));
        assert!(matches!(
            state.reserve(now + Duration::from_secs(4)),
            RetirementReservation::CoolingDown
        ));
        assert!(matches!(
            state.reserve(now + Duration::from_secs(5)),
            RetirementReservation::New(_)
        ));
    }

    #[test]
    fn retirement_queue_state_stale_ticket_cannot_complete_an_aba_replacement() {
        let now = Instant::now();
        let mut state = RetirementState::default();
        let first = match state.reserve(now) {
            RetirementReservation::New(ticket) => ticket,
            _ => panic!("first reservation must allocate"),
        };
        assert!(state.finish(&first));
        let replacement = match state.reserve(now) {
            RetirementReservation::New(ticket) => ticket,
            _ => panic!("replacement must allocate"),
        };
        assert!(!state.finish(&first));
        assert!(!state.fail_terminal(&first, now, SystemTime::now(), Duration::from_secs(5)));
        assert!(matches!(
            state.reserve(now),
            RetirementReservation::Existing(ticket) if Arc::ptr_eq(&ticket.state, &replacement.state)
        ));
    }
}
