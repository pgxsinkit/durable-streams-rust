//! A weak, membership-only index for streams with an expiry policy.
//!
//! The future scanner owns its cursor and performs every liveness, deadline,
//! and retirement decision after a page has been returned. Keeping this index
//! deliberately unaware of those concerns prevents it from retaining streams
//! or taking Store locks while it is scanned.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use crate::store::{Store, StreamState};

/// Requested behavior for the future expiration reaper.
///
/// `Delete` is tier-guarded and activates only after the scanner has completed
/// its initial read-only pass and all delete-safety gates permit admission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ExpirationReaperMode {
    #[default]
    Off,
    Observe,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpirationReaperModeParseError;

impl fmt::Display for ExpirationReaperModeParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("must be exactly off, observe, or delete")
    }
}

impl FromStr for ExpirationReaperMode {
    type Err = ExpirationReaperModeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "observe" => Ok(Self::Observe),
            "delete" => Ok(Self::Delete),
            _ => Err(ExpirationReaperModeParseError),
        }
    }
}

/// Immutable scanner settings parsed at startup.
///
/// The rate limits are capped at one token per nanosecond so the future token
/// pacer can represent their minimum interval without truncation to zero.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExpirationScannerConfig {
    mode: ExpirationReaperMode,
    scan_rate_candidates_per_second: u64,
    delete_rate_deletions_per_second: u64,
    startup_grace_duration: Duration,
    bulk_fraction: BulkFraction,
    clock_jump_threshold_duration: Duration,
}

impl Default for ExpirationScannerConfig {
    fn default() -> Self {
        Self {
            mode: ExpirationReaperMode::Off,
            scan_rate_candidates_per_second: 10_000,
            delete_rate_deletions_per_second: 100,
            startup_grace_duration: Duration::from_secs(60),
            bulk_fraction: BulkFraction::QUARTER,
            clock_jump_threshold_duration: Duration::from_secs(300),
        }
    }
}

impl ExpirationScannerConfig {
    /// Apply one recognized CLI option. Repeated options deliberately replace
    /// the prior value, matching the server's existing last-value-wins parser.
    pub(crate) fn set_cli_value(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--expiry-reaper-mode" => {
                self.mode = value
                    .parse()
                    .map_err(|error: ExpirationReaperModeParseError| format!("{flag} {error}"))?;
            }
            "--expiry-scan-rate" => {
                self.scan_rate_candidates_per_second =
                    parse_positive_rate(flag, value, "candidates")?;
            }
            "--expiry-delete-rate" => {
                self.delete_rate_deletions_per_second =
                    parse_positive_rate(flag, value, "deletions")?;
            }
            "--expiry-startup-grace-seconds" => {
                self.startup_grace_duration = Duration::from_secs(parse_seconds(flag, value)?);
            }
            "--expiry-bulk-fraction" => {
                self.bulk_fraction = parse_bulk_fraction(flag, value)?;
            }
            "--expiry-clock-jump-seconds" => {
                let seconds = parse_seconds(flag, value)?;
                if seconds == 0 {
                    // Zero cannot mean "disabled": the future scanner must
                    // always distinguish ordinary time from a clock jump.
                    return Err(format!("{flag} must be a positive integer (seconds)"));
                }
                self.clock_jump_threshold_duration = Duration::from_secs(seconds);
            }
            _ => return Err(format!("unknown expiration reaper option: {flag}")),
        }
        Ok(())
    }

    pub(crate) const fn mode(&self) -> ExpirationReaperMode {
        self.mode
    }

    pub(crate) const fn scan_rate_candidates_per_second(&self) -> u64 {
        self.scan_rate_candidates_per_second
    }

    pub(crate) const fn delete_rate_deletions_per_second(&self) -> u64 {
        self.delete_rate_deletions_per_second
    }

    pub(crate) const fn startup_grace_duration(&self) -> Duration {
        self.startup_grace_duration
    }

    /// A display-only projection for future status/telemetry. Safety decisions
    /// retain the exact decimal representation below.
    pub(crate) fn bulk_fraction(&self) -> f64 {
        self.bulk_fraction.as_f64()
    }

    pub(crate) const fn clock_jump_threshold_duration(&self) -> Duration {
        self.clock_jump_threshold_duration
    }

    /// Delete-mode activation must stay local-only until tier-aware retirement
    /// exists. `TierConfig::enabled` is deliberately fail-closed for any
    /// current or future non-Off backend.
    pub(crate) fn validate_tier(&self, tier: &crate::tier::TierConfig) -> Result<(), String> {
        if self.mode == ExpirationReaperMode::Delete && tier.enabled() {
            return Err(format!(
                "--expiry-reaper-mode delete requires --tier off; configured tier is {:?}",
                tier.kind
            ));
        }
        Ok(())
    }
}

const MAX_RATE_PER_SECOND: u64 = 1_000_000_000;
const OBSERVATION_PAGE_SIZE: usize = 128;
const IDLE_SCAN_DELAY: Duration = Duration::from_millis(100);

fn parse_positive_rate(flag: &str, value: &str, unit: &str) -> Result<u64, String> {
    match value.parse::<u64>() {
        Ok(rate) if (1..=MAX_RATE_PER_SECOND).contains(&rate) => Ok(rate),
        _ => Err(format!(
            "{flag} must be a positive integer no greater than {MAX_RATE_PER_SECOND} ({unit} per second)"
        )),
    }
}

fn parse_seconds(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} must be a non-negative integer (seconds)"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BulkFraction {
    numerator: u64,
    denominator: u64,
}

impl BulkFraction {
    const QUARTER: Self = Self {
        numerator: 1,
        denominator: 4,
    };

    fn as_f64(self) -> f64 {
        self.numerator as f64 / self.denominator as f64
    }

    /// `due / checked > self`, using `u128` products. The operands are at
    /// most `u64::MAX`, and decimal denominators are capped at 10^18, so both
    /// products are strictly below `u128::MAX`.
    fn exceeded_by(self, due: u64, checked: u64) -> bool {
        checked != 0
            && u128::from(due) * u128::from(self.denominator)
                > u128::from(self.numerator) * u128::from(checked)
    }
}

fn parse_bulk_fraction(flag: &str, value: &str) -> Result<BulkFraction, String> {
    const MAX_DECIMAL_PLACES: usize = 18;
    let invalid = || {
        format!(
            "{flag} must be a decimal in (0, 1] with at most {MAX_DECIMAL_PLACES} digits after the decimal point (exponents are not supported)"
        )
    };

    let (whole, fractional) = match value.split_once('.') {
        Some((whole, fractional)) => (whole, Some(fractional)),
        None => (value, None),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.is_some_and(|digits| {
            digits.is_empty()
                || digits.len() > MAX_DECIMAL_PLACES
                || !digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(invalid());
    }

    let whole = whole.parse::<u64>().map_err(|_| invalid())?;
    let (numerator, denominator) = match fractional {
        Some(digits) => {
            let denominator =
                10_u64.pow(u32::try_from(digits.len()).expect("precision is bounded"));
            let fractional = digits.parse::<u64>().map_err(|_| invalid())?;
            let numerator = whole
                .checked_mul(denominator)
                .and_then(|value| value.checked_add(fractional))
                .ok_or_else(invalid)?;
            (numerator, denominator)
        }
        None => (whole, 1),
    };
    if numerator == 0 || numerator > denominator {
        return Err(invalid());
    }
    let divisor = greatest_common_divisor(numerator, denominator);
    Ok(BulkFraction {
        numerator: numerator / divisor,
        denominator: denominator / divisor,
    })
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// Read-only result from validating one weak expiration-index candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpirationCandidateObservation {
    Live,
    /// Canonical deadline lag captured while holding the stream shared read.
    Due {
        lag: Duration,
    },
    Dead,
    Stale,
}

/// The scanner's effective behavior, distinct from the requested CLI mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ExpirationScannerEffectiveMode {
    #[default]
    Off,
    Observe,
    /// Delete was requested but is still held behind a safety gate.
    DeleteGated,
    /// Delete has passed its local gates and can submit bounded admissions.
    DeleteActive,
}

/// Fixed, identifier-free scanner outcome counters for later telemetry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExpirationOutcomeCounts {
    pub(crate) observed: u64,
    /// Reserved until Store exposes an exact renewal-vs-other cancellation
    /// result; this slice deliberately does not infer it from a ticket.
    pub(crate) renewed: u64,
    pub(crate) fenced: u64,
    pub(crate) soft_deleted: u64,
    pub(crate) reaped: u64,
    pub(crate) stale: u64,
    pub(crate) failed: u64,
}

/// One immutable O(1) health projection. It intentionally contains no path,
/// stream ID collection, or candidate Arc; callers cannot retain Store state.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ExpirationScannerSnapshot {
    pub(crate) requested_mode: ExpirationReaperMode,
    pub(crate) effective_mode: ExpirationScannerEffectiveMode,
    pub(crate) running: bool,
    pub(crate) initial_observe_pass_complete: bool,
    pub(crate) startup_grace_elapsed: bool,
    pub(crate) deletion_eligible: bool,
    pub(crate) bulk_paused: bool,
    pub(crate) clock_paused: bool,
    pub(crate) index_entry_count: usize,
    pub(crate) pass_sequence: u64,
    pub(crate) current_page_count: u64,
    pub(crate) last_scanned_stream_id: Option<u64>,
    pub(crate) cursor_wrapped: bool,
    pub(crate) current_checked: u64,
    pub(crate) current_due: u64,
    pub(crate) completed_checked: u64,
    pub(crate) completed_due: u64,
    pub(crate) bulk_threshold_numerator: u64,
    pub(crate) bulk_threshold_denominator: u64,
    pub(crate) current_due_fraction: f64,
    pub(crate) completed_due_fraction: f64,
    pub(crate) total_checked: u64,
    pub(crate) total_due: u64,
    pub(crate) total_pages: u64,
    pub(crate) total_passes: u64,
    pub(crate) proactive_admission_attempts: u64,
    pub(crate) outcomes: ExpirationOutcomeCounts,
    pub(crate) last_completed_pass_wall_time: Option<SystemTime>,
    pub(crate) last_completed_pass_duration: Option<Duration>,
    pub(crate) last_successful_scan_wall_time: Option<SystemTime>,
    pub(crate) latest_due_lag: Option<Duration>,
    pub(crate) current_max_due_lag: Option<Duration>,
    pub(crate) completed_max_due_lag: Option<Duration>,
    pub(crate) latest_clock_drift: Option<Duration>,
}

/// Level-triggered state shared with the future delete-mode controller.
pub(crate) struct ExpirationScannerStatus {
    initial_observe_pass_complete: std::sync::atomic::AtomicBool,
    initial_observe_pass: tokio::sync::Notify,
    started_at: Instant,
    startup_grace_duration: Duration,
    requested_mode: ExpirationReaperMode,
    delete_requested: bool,
    bulk_fraction: BulkFraction,
    clock_jump_threshold_duration: Duration,
    safety: Mutex<DeleteSafetyState>,
}

impl ExpirationScannerStatus {
    fn new(config: &ExpirationScannerConfig) -> Self {
        Self::new_at(config, Instant::now())
    }

    fn new_at(config: &ExpirationScannerConfig, started_at: Instant) -> Self {
        let status = Self {
            initial_observe_pass_complete: std::sync::atomic::AtomicBool::new(false),
            initial_observe_pass: tokio::sync::Notify::new(),
            started_at,
            startup_grace_duration: config.startup_grace_duration(),
            requested_mode: config.mode(),
            delete_requested: config.mode() == ExpirationReaperMode::Delete,
            bulk_fraction: config.bulk_fraction,
            clock_jump_threshold_duration: config.clock_jump_threshold_duration(),
            safety: Mutex::new(DeleteSafetyState::default()),
        };
        // Publish explicit zeroes so a newly started/off scanner reports both
        // current gauges as zero rather than retaining a prior process value.
        crate::telemetry::record_expiry_page(crate::telemetry::ExpiryPageTelemetry {
            index_entries: 0,
            checked: 0,
            due: 0,
            observed: 0,
            stale: 0,
            latest_due_lag_seconds: None,
            oldest_due_lag_seconds: None,
            bulk_guard_paused: false,
            completed_pass_duration_seconds: None,
        });
        status
    }

    fn mark_initial_observe_pass_complete(&self) {
        let changed = {
            let mut safety = self.lock_safety();
            if safety.initial_observe_pass_complete {
                false
            } else {
                safety.initial_observe_pass_complete = true;
                true
            }
        };
        self.publish_initial_observe_pass(changed);
    }

    fn publish_initial_observe_pass(&self, changed: bool) {
        if changed
            && !self
                .initial_observe_pass_complete
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.initial_observe_pass.notify_waiters();
        }
    }

    fn lock_safety(&self) -> std::sync::MutexGuard<'_, DeleteSafetyState> {
        self.safety
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn set_running(&self, running: bool) {
        self.lock_safety().running = running;
    }

    pub(crate) fn initial_observe_pass_complete(&self) -> bool {
        self.initial_observe_pass_complete
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Wait until a complete page sequence has observed the current index at
    /// least once. This is level-triggered, so late callers return immediately.
    pub(crate) async fn wait_initial_observe_pass(&self) {
        loop {
            let notified = self.initial_observe_pass.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.initial_observe_pass_complete() {
                return;
            }
            notified.await;
        }
    }

    /// Delete activation consults this monotonic startup-grace boundary; it
    /// never changes the observer's candidate classification.
    pub(crate) fn startup_grace_active_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started_at) < self.startup_grace_duration
    }

    /// Record one fully classified page before delete activation inspects it.
    /// This small wrapper keeps the safety-state unit tests independent from
    /// scanner wall/monotonic clock plumbing.
    fn record_observe_page(&self, checked: u64, due: u64, pass_complete: bool) {
        self.record_scanned_page(ScannerPageAccounting {
            checked,
            due,
            stale: 0,
            index_entry_count: 0,
            last_scanned_stream_id: None,
            cursor_wrapped: false,
            pass_complete,
            latest_due_lag: None,
            max_due_lag: None,
            wall: SystemTime::now(),
            monotonic: Instant::now(),
        });
    }

    fn record_scanned_page(&self, page: ScannerPageAccounting) {
        let (initial_transition, telemetry) = {
            let mut safety = self.lock_safety();
            if safety.current_pass_started_monotonic.is_none() {
                safety.current_pass_started_monotonic = Some(page.monotonic);
            }
            safety.index_entry_count = page.index_entry_count;
            safety.current_page_count = safety.current_page_count.saturating_add(1);
            if page.last_scanned_stream_id.is_some() {
                safety.last_scanned_stream_id = page.last_scanned_stream_id;
            }
            safety.cursor_wrapped = page.cursor_wrapped;
            safety.current_checked = safety.current_checked.saturating_add(page.checked);
            safety.current_due = safety.current_due.saturating_add(page.due);
            safety.total_checked = safety.total_checked.saturating_add(page.checked);
            safety.total_due = safety.total_due.saturating_add(page.due);
            safety.total_pages = safety.total_pages.saturating_add(1);
            safety.last_successful_scan_wall_time = Some(page.wall);
            safety.outcomes.observed = safety.outcomes.observed.saturating_add(page.checked);
            safety.outcomes.stale = safety.outcomes.stale.saturating_add(page.stale);
            safety.latest_due_lag = page.latest_due_lag;
            safety.current_max_due_lag = max_duration(safety.current_max_due_lag, page.max_due_lag);
            if self
                .bulk_fraction
                .exceeded_by(safety.current_due, safety.current_checked)
            {
                safety.bulk_paused = true;
            }
            let (initial_transition, completed_pass_duration) = if page.pass_complete {
                safety.completed_checked = safety.current_checked;
                safety.completed_due = safety.current_due;
                safety.completed_max_due_lag = safety.current_max_due_lag;
                safety.last_completed_pass_wall_time = Some(page.wall);
                let duration = safety
                    .current_pass_started_monotonic
                    .map(|started| page.monotonic.saturating_duration_since(started));
                safety.last_completed_pass_duration = duration;
                safety.total_passes = safety.total_passes.saturating_add(1);
                safety.current_checked = 0;
                safety.current_due = 0;
                safety.current_page_count = 0;
                safety.current_max_due_lag = None;
                safety.current_pass_started_monotonic = None;
                let transition = if safety.initial_observe_pass_complete {
                    false
                } else {
                    safety.initial_observe_pass_complete = true;
                    true
                };
                (transition, duration)
            } else {
                (false, None)
            };
            (
                initial_transition,
                crate::telemetry::ExpiryPageTelemetry {
                    index_entries: u64::try_from(page.index_entry_count).unwrap_or(u64::MAX),
                    checked: page.checked,
                    due: page.due,
                    observed: page.checked,
                    stale: page.stale,
                    latest_due_lag_seconds: page.latest_due_lag.map(|lag| lag.as_secs_f64()),
                    oldest_due_lag_seconds: page.max_due_lag.map(|lag| lag.as_secs_f64()),
                    bulk_guard_paused: safety.bulk_paused,
                    completed_pass_duration_seconds: completed_pass_duration
                        .map(|duration| duration.as_secs_f64()),
                },
            )
        };
        self.publish_initial_observe_pass(initial_transition);
        crate::telemetry::record_expiry_page(telemetry);
    }

    /// Sample exactly at the boundary after observing a page and before the
    /// scanner sleeps. The first sample only establishes a baseline.
    fn sample_clock(&self, wall: SystemTime, monotonic: Instant) {
        let latest_clock_drift = {
            let mut safety = self.lock_safety();
            if let Some(previous) = safety.last_clock_sample {
                let wall_elapsed = wall.duration_since(previous.wall);
                let monotonic_elapsed = monotonic.checked_duration_since(previous.monotonic);
                match (wall_elapsed, monotonic_elapsed) {
                    (Ok(wall_elapsed), Some(monotonic_elapsed)) => {
                        let divergence = if wall_elapsed >= monotonic_elapsed {
                            wall_elapsed - monotonic_elapsed
                        } else {
                            monotonic_elapsed - wall_elapsed
                        };
                        safety.latest_clock_drift = Some(divergence);
                        if divergence > self.clock_jump_threshold_duration {
                            safety.clock_paused = true;
                        }
                    }
                    // A backward wall clock or impossible monotonic ordering is
                    // unsafe for deletion activation, but remains harmless to the
                    // read-only observer and lazy request-time expiration.
                    (Err(_), Some(monotonic_elapsed)) => {
                        let wall_reversal =
                            previous.wall.duration_since(wall).unwrap_or(Duration::ZERO);
                        safety.latest_clock_drift =
                            Some(wall_reversal.saturating_add(monotonic_elapsed));
                        safety.clock_paused = true;
                    }
                    (Ok(wall_elapsed), None) => {
                        let monotonic_reversal = previous
                            .monotonic
                            .checked_duration_since(monotonic)
                            .unwrap_or(Duration::MAX);
                        safety.latest_clock_drift =
                            Some(wall_elapsed.saturating_add(monotonic_reversal));
                        safety.clock_paused = true;
                    }
                    (Err(_), None) => {
                        let wall_reversal =
                            previous.wall.duration_since(wall).unwrap_or(Duration::ZERO);
                        let monotonic_reversal = previous
                            .monotonic
                            .checked_duration_since(monotonic)
                            .unwrap_or(Duration::MAX);
                        safety.latest_clock_drift = Some(if wall_reversal >= monotonic_reversal {
                            wall_reversal - monotonic_reversal
                        } else {
                            monotonic_reversal - wall_reversal
                        });
                        safety.clock_paused = true;
                    }
                }
            }
            safety.last_clock_sample = Some(ClockSample { wall, monotonic });
            safety.latest_clock_drift
        };
        if let Some(drift) = latest_clock_drift {
            crate::telemetry::record_expiry_clock_drift(drift.as_secs_f64());
        }
    }

    /// Read the safety projection used by the page-level Delete admission gate.
    pub(crate) fn safety_snapshot_at(&self, now: Instant) -> DeleteSafetySnapshot {
        let safety = self.lock_safety();
        let startup_grace_elapsed = !self.startup_grace_active_at(now);
        let initial_observe_pass_complete = safety.initial_observe_pass_complete;
        DeleteSafetySnapshot {
            initial_observe_pass_complete,
            startup_grace_elapsed,
            deletion_eligible: self.delete_requested
                && initial_observe_pass_complete
                && startup_grace_elapsed
                && !safety.bulk_paused
                && !safety.clock_paused,
            bulk_paused: safety.bulk_paused,
            clock_paused: safety.clock_paused,
            current_checked: safety.current_checked,
            current_due: safety.current_due,
            completed_checked: safety.completed_checked,
            completed_due: safety.completed_due,
        }
    }

    pub(crate) fn snapshot_at(&self, now: Instant) -> ExpirationScannerSnapshot {
        let safety = self.lock_safety();
        let startup_grace_elapsed = !self.startup_grace_active_at(now);
        let deletion_eligible = self.delete_requested
            && safety.initial_observe_pass_complete
            && startup_grace_elapsed
            && !safety.bulk_paused
            && !safety.clock_paused;
        let effective_mode = match self.requested_mode {
            ExpirationReaperMode::Off => ExpirationScannerEffectiveMode::Off,
            ExpirationReaperMode::Observe => ExpirationScannerEffectiveMode::Observe,
            ExpirationReaperMode::Delete if deletion_eligible && safety.running => {
                ExpirationScannerEffectiveMode::DeleteActive
            }
            ExpirationReaperMode::Delete => ExpirationScannerEffectiveMode::DeleteGated,
        };
        ExpirationScannerSnapshot {
            requested_mode: self.requested_mode,
            effective_mode,
            running: safety.running,
            initial_observe_pass_complete: safety.initial_observe_pass_complete,
            startup_grace_elapsed,
            deletion_eligible,
            bulk_paused: safety.bulk_paused,
            clock_paused: safety.clock_paused,
            index_entry_count: safety.index_entry_count,
            pass_sequence: safety.total_passes.saturating_add(1),
            current_page_count: safety.current_page_count,
            last_scanned_stream_id: safety.last_scanned_stream_id,
            cursor_wrapped: safety.cursor_wrapped,
            current_checked: safety.current_checked,
            current_due: safety.current_due,
            completed_checked: safety.completed_checked,
            completed_due: safety.completed_due,
            bulk_threshold_numerator: self.bulk_fraction.numerator,
            bulk_threshold_denominator: self.bulk_fraction.denominator,
            current_due_fraction: due_fraction(safety.current_due, safety.current_checked),
            completed_due_fraction: due_fraction(safety.completed_due, safety.completed_checked),
            total_checked: safety.total_checked,
            total_due: safety.total_due,
            total_pages: safety.total_pages,
            total_passes: safety.total_passes,
            proactive_admission_attempts: safety.proactive_admission_attempts,
            outcomes: safety.outcomes,
            last_completed_pass_wall_time: safety.last_completed_pass_wall_time,
            last_completed_pass_duration: safety.last_completed_pass_duration,
            last_successful_scan_wall_time: safety.last_successful_scan_wall_time,
            latest_due_lag: safety.latest_due_lag,
            current_max_due_lag: safety.current_max_due_lag,
            completed_max_due_lag: safety.completed_max_due_lag,
            latest_clock_drift: safety.latest_clock_drift,
        }
    }

    fn record_proactive_admission_attempt(&self) {
        let mut safety = self.lock_safety();
        safety.proactive_admission_attempts = safety.proactive_admission_attempts.saturating_add(1);
    }

    fn record_proactive_outcome(&self, result: &crate::store::ExplicitRetirementResult) {
        let outcome = {
            let mut safety = self.lock_safety();
            match result {
                // Owner means only that logical retirement admitted this stream.
                // Physical completion is executor-owned and belongs to 0ln-b, so
                // this snapshot deliberately leaves `reaped` at zero here.
                crate::store::ExplicitRetirementResult::Owner(_) => None,
                // A duplicate ticket did not apply a new fence. Fence telemetry
                // is emitted by Store only for the exact successful transition.
                crate::store::ExplicitRetirementResult::Existing(_) => None,
                // Store emits soft_deleted only after the exact durable
                // tombstone transition succeeds; observing an old tombstone is
                // not another transition.
                crate::store::ExplicitRetirementResult::Gone => None,
                crate::store::ExplicitRetirementResult::Missing
                | crate::store::ExplicitRetirementResult::Stale => {
                    safety.outcomes.stale = safety.outcomes.stale.saturating_add(1);
                    Some(crate::telemetry::ExpiryOutcome::Stale)
                }
                crate::store::ExplicitRetirementResult::Renewed(_) => {
                    safety.outcomes.renewed = safety.outcomes.renewed.saturating_add(1);
                    Some(crate::telemetry::ExpiryOutcome::Renewed)
                }
                crate::store::ExplicitRetirementResult::Cancelled(_)
                | crate::store::ExplicitRetirementResult::Rejected(_)
                | crate::store::ExplicitRetirementResult::Unavailable => {
                    safety.outcomes.failed = safety.outcomes.failed.saturating_add(1);
                    Some(crate::telemetry::ExpiryOutcome::Failed)
                }
            }
        };
        if let Some(outcome) = outcome {
            crate::telemetry::record_expiry_outcome(crate::telemetry::ExpiryOutcomeDelta {
                outcome,
                count: 1,
            });
        }
    }

    #[cfg(test)]
    fn proactive_admission_attempts(&self) -> u64 {
        self.lock_safety().proactive_admission_attempts
    }
}

#[derive(Clone, Copy)]
struct ClockSample {
    wall: SystemTime,
    monotonic: Instant,
}

struct ScannerPageAccounting {
    checked: u64,
    due: u64,
    stale: u64,
    index_entry_count: usize,
    last_scanned_stream_id: Option<u64>,
    cursor_wrapped: bool,
    pass_complete: bool,
    latest_due_lag: Option<Duration>,
    max_due_lag: Option<Duration>,
    wall: SystemTime,
    monotonic: Instant,
}

#[derive(Default)]
struct DeleteSafetyState {
    running: bool,
    initial_observe_pass_complete: bool,
    index_entry_count: usize,
    current_page_count: u64,
    last_scanned_stream_id: Option<u64>,
    cursor_wrapped: bool,
    current_checked: u64,
    current_due: u64,
    completed_checked: u64,
    completed_due: u64,
    total_checked: u64,
    total_due: u64,
    total_pages: u64,
    total_passes: u64,
    proactive_admission_attempts: u64,
    outcomes: ExpirationOutcomeCounts,
    current_pass_started_monotonic: Option<Instant>,
    last_completed_pass_wall_time: Option<SystemTime>,
    last_completed_pass_duration: Option<Duration>,
    last_successful_scan_wall_time: Option<SystemTime>,
    latest_due_lag: Option<Duration>,
    current_max_due_lag: Option<Duration>,
    completed_max_due_lag: Option<Duration>,
    latest_clock_drift: Option<Duration>,
    bulk_paused: bool,
    clock_paused: bool,
    last_clock_sample: Option<ClockSample>,
}

fn max_duration(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Read-only deletion-safety state reserved for future activation and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeleteSafetySnapshot {
    pub(crate) initial_observe_pass_complete: bool,
    pub(crate) startup_grace_elapsed: bool,
    pub(crate) deletion_eligible: bool,
    pub(crate) bulk_paused: bool,
    pub(crate) clock_paused: bool,
    pub(crate) current_checked: u64,
    pub(crate) current_due: u64,
    pub(crate) completed_checked: u64,
    pub(crate) completed_due: u64,
}

impl DeleteSafetySnapshot {
    pub(crate) fn current_due_fraction(&self) -> f64 {
        due_fraction(self.current_due, self.current_checked)
    }

    pub(crate) fn completed_due_fraction(&self) -> f64 {
        due_fraction(self.completed_due, self.completed_checked)
    }
}

fn due_fraction(due: u64, checked: u64) -> f64 {
    if checked == 0 {
        0.0
    } else {
        due as f64 / checked as f64
    }
}

/// Supervised process-lifetime expiration scanner.
///
/// Off mode creates no task. Observe stays read-only; Delete admits only after
/// its read-only safety gates are satisfied.
pub(crate) struct ExpirationScanner {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
    status: Arc<ExpirationScannerStatus>,
}

impl ExpirationScanner {
    pub(crate) fn start(store: &Arc<Store>, config: ExpirationScannerConfig) -> Self {
        let status = Arc::new(ExpirationScannerStatus::new(&config));
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        if config.mode() == ExpirationReaperMode::Off {
            // No background loop in Off mode, while callers waiting on the
            // future activation boundary still receive a completed level state.
            status.mark_initial_observe_pass_complete();
            return Self {
                shutdown,
                task: None,
                status,
            };
        }

        status.set_running(true);
        let store = Arc::downgrade(store);
        let task_status = Arc::clone(&status);
        let task = tokio::spawn(async move {
            match config.mode() {
                ExpirationReaperMode::Observe | ExpirationReaperMode::Delete => {
                    run_scanner(store, config, task_status, shutdown_rx).await;
                }
                ExpirationReaperMode::Off => unreachable!("off mode starts no scanner task"),
            }
        });
        Self {
            shutdown,
            task: Some(task),
            status,
        }
    }

    pub(crate) fn status(&self) -> &Arc<ExpirationScannerStatus> {
        &self.status
    }

    pub(crate) fn snapshot_at(&self, now: Instant) -> ExpirationScannerSnapshot {
        self.status.snapshot_at(now)
    }

    pub(crate) async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for ExpirationScanner {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct ObservedPage {
    next_cursor: ExpirationCursor,
    pass_complete: bool,
    candidate_count: usize,
    index_entry_count: usize,
    last_scanned_stream_id: Option<u64>,
    cursor_wrapped: bool,
    checked_count: u64,
    due_count: usize,
    stale_count: u64,
    latest_due_lag: Option<Duration>,
    max_due_lag: Option<Duration>,
    due_streams: Vec<Arc<StreamState>>,
}

async fn run_scanner(
    store: Weak<Store>,
    config: ExpirationScannerConfig,
    status: Arc<ExpirationScannerStatus>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let _running = ScannerRunningGuard {
        status: Arc::clone(&status),
    };
    let mut cursor = ExpirationCursor::start();
    let mut delete_pacer = DeletePacer::new(config.delete_rate_deletions_per_second());
    loop {
        if *shutdown.borrow() {
            return;
        }
        let Some(store) = store.upgrade() else {
            return;
        };
        // The initial full pass is unconditionally observation-only. Capture
        // this before recording the page that may complete that pass.
        let initial_pass_complete_at_page_start = status.initial_observe_pass_complete();
        let observed = observe_page(&store, cursor, SystemTime::now());
        cursor = observed.next_cursor;
        let candidate_count = observed.candidate_count;
        status.record_scanned_page(ScannerPageAccounting {
            checked: observed.checked_count,
            due: u64::try_from(observed.due_count).expect("page due count fits u64"),
            stale: observed.stale_count,
            index_entry_count: observed.index_entry_count,
            last_scanned_stream_id: observed.last_scanned_stream_id,
            cursor_wrapped: observed.cursor_wrapped,
            pass_complete: observed.pass_complete,
            latest_due_lag: observed.latest_due_lag,
            max_due_lag: observed.max_due_lag,
            wall: SystemTime::now(),
            monotonic: Instant::now(),
        });
        status.sample_clock(SystemTime::now(), Instant::now());
        // Refresh the O(1) retirement age gauge while scanning so a retained
        // idle fence continues to report its current age between transitions.
        if let Some(executor) = store.retirement_executor() {
            executor.emit_expiry_telemetry();
        }
        let safety = status.safety_snapshot_at(Instant::now());
        if !admit_due_candidates(
            &store,
            &status,
            &mut delete_pacer,
            &mut shutdown,
            DeletePageDecision {
                mode: config.mode(),
                initial_pass_complete_at_page_start,
                safety,
            },
            observed.due_streams,
        )
        .await
        {
            return;
        }
        let delay = page_pacing_delay(config.scan_rate_candidates_per_second(), candidate_count);
        drop(store);
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

struct ScannerRunningGuard {
    status: Arc<ExpirationScannerStatus>,
}

impl Drop for ScannerRunningGuard {
    fn drop(&mut self) {
        self.status.set_running(false);
    }
}

/// Return false only when shutdown interrupts pacing. This is the sole
/// activation boundary: all page candidates have already been classified and
/// counted, and a failed safety gate admits none of them.
#[derive(Clone, Copy)]
struct DeletePageDecision {
    mode: ExpirationReaperMode,
    initial_pass_complete_at_page_start: bool,
    safety: DeleteSafetySnapshot,
}

async fn admit_due_candidates(
    store: &Arc<Store>,
    status: &ExpirationScannerStatus,
    delete_pacer: &mut DeletePacer,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    decision: DeletePageDecision,
    due_streams: Vec<Arc<StreamState>>,
) -> bool {
    if decision.mode != ExpirationReaperMode::Delete
        || !decision.initial_pass_complete_at_page_start
        || !decision.safety.deletion_eligible
    {
        return true;
    }
    for stream in due_streams {
        if !delete_pacer.wait_for_permit(shutdown).await {
            return false;
        }
        // A Store retirement future is awaited to completion through logical
        // handoff so its pre-logical reservation cannot be dropped mid-flight.
        // Its ticket/physical phase remains executor-owned; the scanner waits
        // on neither completion.
        status.record_proactive_admission_attempt();
        let result = store.retire_proactive_expiry(Arc::clone(&stream)).await;
        status.record_proactive_outcome(&result);
    }
    true
}

struct DeletePacer {
    interval: Duration,
    next_permit: Option<Instant>,
}

impl DeletePacer {
    fn new(rate_per_second: u64) -> Self {
        Self {
            interval: delete_pacing_interval(rate_per_second),
            next_permit: None,
        }
    }

    async fn wait_for_permit(&mut self, shutdown: &mut tokio::sync::watch::Receiver<bool>) -> bool {
        if *shutdown.borrow() {
            return false;
        }
        if let Some(next_permit) = self.next_permit {
            let delay = next_permit.saturating_duration_since(Instant::now());
            if !delay.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    changed = shutdown.changed() => {
                        return changed.is_ok() && !*shutdown.borrow();
                    }
                }
            }
        }
        if *shutdown.borrow() {
            return false;
        }
        self.next_permit = Some(
            Instant::now()
                .checked_add(self.interval)
                .expect("delete pacing interval is bounded"),
        );
        true
    }
}

fn observe_page(store: &Store, cursor: ExpirationCursor, now: SystemTime) -> ObservedPage {
    let page = store.expiration_page(cursor, OBSERVATION_PAGE_SIZE);
    let mut checked_count = 0u64;
    let mut due_count = 0;
    let mut stale_count = 0u64;
    let mut latest_due_lag = None;
    let mut max_due_lag = None;
    let mut due_streams = Vec::new();
    for candidate in &page.candidates {
        match store.observe_expiration_candidate(candidate, now) {
            ExpirationCandidateObservation::Due { lag } => {
                checked_count = checked_count.saturating_add(1);
                due_count += 1;
                latest_due_lag = Some(lag);
                max_due_lag = max_duration(max_due_lag, Some(lag));
                if let Some(stream) = candidate.stream.upgrade() {
                    due_streams.push(stream);
                }
            }
            ExpirationCandidateObservation::Live => {
                checked_count = checked_count.saturating_add(1);
            }
            ExpirationCandidateObservation::Dead => {}
            ExpirationCandidateObservation::Stale => {
                stale_count = stale_count.saturating_add(1);
            }
        }
    }
    ObservedPage {
        next_cursor: page.next_cursor,
        pass_complete: page.pass_complete,
        candidate_count: page.candidates.len(),
        index_entry_count: page.entry_count,
        last_scanned_stream_id: page.candidates.last().map(|candidate| candidate.stream_id),
        cursor_wrapped: page.wrapped,
        checked_count,
        due_count,
        stale_count,
        latest_due_lag,
        max_due_lag,
        due_streams,
    }
}

fn page_pacing_delay(rate_per_second: u64, candidate_count: usize) -> Duration {
    if candidate_count == 0 {
        return IDLE_SCAN_DELAY;
    }
    let nanos =
        (u128::from(candidate_count as u64) * 1_000_000_000).div_ceil(u128::from(rate_per_second));
    Duration::from_nanos(u64::try_from(nanos).expect("page pacing is bounded by page size"))
}

fn delete_pacing_interval(rate_per_second: u64) -> Duration {
    let nanos = 1_000_000_000_u128.div_ceil(u128::from(rate_per_second));
    Duration::from_nanos(u64::try_from(nanos).expect("delete pacing interval fits u64"))
}

/// Stable round-robin position owned by an expiration scanner.
///
/// `after` is the last ID yielded in this pass. `anchor` is set only for a
/// caller that deliberately begins after a particular ID; it lets later pages
/// finish the wrapped lower half without re-visiting the upper half.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExpirationCursor {
    after: Option<u64>,
    anchor: Option<u64>,
    wrapped: bool,
}

impl ExpirationCursor {
    pub(crate) const fn start() -> Self {
        Self {
            after: None,
            anchor: None,
            wrapped: false,
        }
    }

    /// Begin one round-robin pass strictly after `stream_id`, wrapping once to
    /// include lower IDs and `stream_id` itself if it remains registered.
    pub(crate) const fn after(stream_id: u64) -> Self {
        Self {
            after: Some(stream_id),
            anchor: Some(stream_id),
            wrapped: false,
        }
    }
}

/// One weak candidate copied out of the index lock.
#[derive(Clone)]
pub(crate) struct ExpirationCandidate {
    pub(crate) stream_id: u64,
    pub(crate) stream: Weak<StreamState>,
}

/// A bounded page plus the state needed to continue the same pass.
pub(crate) struct ExpirationPage {
    pub(crate) candidates: Vec<ExpirationCandidate>,
    /// Cardinality captured under the same index lock as this bounded page.
    pub(crate) entry_count: usize,
    pub(crate) next_cursor: ExpirationCursor,
    /// True once this pass has entered its wrapped, lower-ID half.
    pub(crate) wrapped: bool,
    /// True only when this call has exhausted the current pass.
    pub(crate) pass_complete: bool,
}

/// Weak membership for streams that have an expiration policy.
///
/// Dead weak entries are intentionally returned in bounded pages rather than
/// swept globally. The scanner can call [`Self::prune_dead`] for a candidate it
/// observed dead, keeping each small page O(limit) and avoiding an O(total)
/// stale-entry pass under this lock. Correct Store wiring will unregister an
/// identity before its final strong reference is dropped, so ordinary index
/// cardinality tracks currently registered expiring identities.
#[derive(Default)]
pub(crate) struct ExpiringStreams {
    entries: Mutex<BTreeMap<u64, Weak<StreamState>>>,
}

impl ExpiringStreams {
    /// Register this exact identity. Re-registering it is idempotent; a live
    /// different identity at the same stable ID is replaced as a new occupant.
    pub(crate) fn register_exact(&self, stream: &Arc<StreamState>) {
        self.register_at_id(stream.id, stream);
    }

    fn register_at_id(&self, stream_id: u64, stream: &Arc<StreamState>) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(&stream_id)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, stream))
        {
            return;
        }
        entries.insert(stream_id, Arc::downgrade(stream));
    }

    /// Remove only the exact identity currently registered under its stable ID.
    /// A stale old Arc therefore cannot remove a replacement that reuses the ID.
    pub(crate) fn unregister_exact(&self, stream: &Arc<StreamState>) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let exact = entries
            .get(&stream.id)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, stream));
        if exact {
            entries.remove(&stream.id);
        }
        exact
    }

    /// Remove a dead candidate observed in a page, but never a replacement.
    pub(crate) fn prune_dead(&self, candidate: &ExpirationCandidate) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dead_and_same = entries.get(&candidate.stream_id).is_some_and(|current| {
            current.upgrade().is_none() && current.ptr_eq(&candidate.stream)
        });
        if dead_and_same {
            entries.remove(&candidate.stream_id);
        }
        dead_and_same
    }

    /// Remove a live candidate that was found stale outside the index lock.
    /// The candidate's upgraded Arc must still be the current occupant, so a
    /// replacement at the same stable ID cannot be removed accidentally.
    pub(crate) fn prune_stale(
        &self,
        candidate: &ExpirationCandidate,
        stream: &Arc<StreamState>,
    ) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let exact = entries
            .get(&candidate.stream_id)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, stream));
        if exact {
            entries.remove(&candidate.stream_id);
        }
        exact
    }

    /// Return one bounded round-robin page without upgrading a weak reference
    /// or consulting Store state under the index lock.
    pub(crate) fn page(&self, cursor: ExpirationCursor, limit: usize) -> ExpirationPage {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry_count = entries.len();
        if entries.is_empty() {
            return ExpirationPage {
                candidates: Vec::new(),
                entry_count,
                next_cursor: ExpirationCursor::start(),
                wrapped: cursor.wrapped,
                pass_complete: true,
            };
        }
        if limit == 0 {
            return ExpirationPage {
                candidates: Vec::new(),
                entry_count,
                next_cursor: cursor,
                wrapped: cursor.wrapped,
                pass_complete: false,
            };
        }

        let mut candidates = Vec::with_capacity(limit.min(entries.len()));
        let mut wrapped = cursor.wrapped;
        let mut complete = false;
        if cursor.wrapped {
            let anchor = cursor
                .anchor
                .expect("a wrapped expiration cursor always has an anchor");
            let after = cursor
                .after
                .expect("a wrapped expiration cursor always has a last ID");
            complete = collect_page(
                entries.range((Excluded(after), Included(anchor))),
                &mut candidates,
                limit,
            );
        } else {
            let upper_exhausted = match cursor.after {
                Some(after) => collect_page(
                    entries.range((Excluded(after), Unbounded)),
                    &mut candidates,
                    limit,
                ),
                None => collect_page(entries.iter(), &mut candidates, limit),
            };
            if upper_exhausted {
                if let Some(anchor) = cursor.anchor {
                    if candidates.len() < limit {
                        wrapped = true;
                        complete = collect_page(
                            entries.range((Unbounded, Included(anchor))),
                            &mut candidates,
                            limit,
                        );
                    }
                } else {
                    complete = true;
                }
            }
        }

        let next_cursor = if complete {
            ExpirationCursor::start()
        } else {
            ExpirationCursor {
                after: candidates.last().map(|candidate| candidate.stream_id),
                anchor: cursor.anchor,
                wrapped,
            }
        };
        ExpirationPage {
            candidates,
            entry_count,
            next_cursor,
            wrapped,
            pass_complete: complete,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

    #[cfg(test)]
    fn register_replacement_for_test(&self, stream_id: u64, replacement: &Arc<StreamState>) {
        self.register_at_id(stream_id, replacement);
    }

    /// Seed a contiguous test-only range of dead entries without allocating or
    /// retaining matching `StreamState`s. The production page/cursor/prune
    /// paths still operate on this exact B-tree and its real `Weak` entries.
    #[cfg(test)]
    fn seed_dead_range_for_test(&self, start: u64, count: usize) {
        let end = start
            .checked_add(u64::try_from(count).expect("test entry count fits u64"))
            .expect("test entry range fits u64");
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(entries.is_empty(), "scale fixture seeds one fresh index");
        entries.extend((start..end).map(|stream_id| (stream_id, Weak::new())));
    }
}

fn collect_page<'a>(
    mut entries: impl Iterator<Item = (&'a u64, &'a Weak<StreamState>)>,
    output: &mut Vec<ExpirationCandidate>,
    limit: usize,
) -> bool {
    while output.len() < limit {
        let Some((stream_id, stream)) = entries.next() else {
            return true;
        };
        output.push(ExpirationCandidate {
            stream_id: *stream_id,
            stream: stream.clone(),
        });
    }
    entries.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CreateResult, Store, StreamConfig};
    use crate::tier::{TierConfig, TierKind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::UNIX_EPOCH;

    #[test]
    fn scanner_config_defaults_and_valid_cli_overrides_are_typed() {
        let mut config = ExpirationScannerConfig::default();
        assert_eq!(config.mode(), ExpirationReaperMode::Off);
        assert_eq!(config.scan_rate_candidates_per_second(), 10_000);
        assert_eq!(config.delete_rate_deletions_per_second(), 100);
        assert_eq!(config.startup_grace_duration(), Duration::from_secs(60));
        assert_eq!(config.bulk_fraction(), 0.25);
        assert_eq!(config.bulk_fraction, BulkFraction::QUARTER);
        assert_eq!(
            config.clock_jump_threshold_duration(),
            Duration::from_secs(300)
        );

        for (flag, value) in [
            ("--expiry-reaper-mode", "delete"),
            ("--expiry-scan-rate", "9999"),
            ("--expiry-delete-rate", "99"),
            ("--expiry-startup-grace-seconds", "0"),
            ("--expiry-bulk-fraction", "1"),
            ("--expiry-clock-jump-seconds", "1"),
        ] {
            config.set_cli_value(flag, value).unwrap();
        }
        assert_eq!(config.mode(), ExpirationReaperMode::Delete);
        assert_eq!(config.scan_rate_candidates_per_second(), 9999);
        assert_eq!(config.delete_rate_deletions_per_second(), 99);
        assert_eq!(config.startup_grace_duration(), Duration::ZERO);
        assert_eq!(config.bulk_fraction(), 1.0);
        assert_eq!(
            config.bulk_fraction,
            BulkFraction {
                numerator: 1,
                denominator: 1
            }
        );
        assert_eq!(
            config.clock_jump_threshold_duration(),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn scanner_mode_is_exact_lowercase_and_delete_is_accepted() {
        assert_eq!("off".parse(), Ok(ExpirationReaperMode::Off));
        assert_eq!("observe".parse(), Ok(ExpirationReaperMode::Observe));
        assert_eq!("delete".parse(), Ok(ExpirationReaperMode::Delete));
        for invalid in ["Off", "DELETE", "delete ", "", "scan"] {
            assert_eq!(
                invalid.parse::<ExpirationReaperMode>(),
                Err(ExpirationReaperModeParseError)
            );
        }
    }

    #[test]
    fn scanner_config_rejects_invalid_values_with_flag_specific_errors() {
        let mut config = ExpirationScannerConfig::default();
        for (flag, value) in [
            ("--expiry-reaper-mode", "Delete"),
            ("--expiry-scan-rate", "0"),
            ("--expiry-scan-rate", "-1"),
            ("--expiry-scan-rate", "1000000001"),
            ("--expiry-scan-rate", "18446744073709551616"),
            ("--expiry-delete-rate", "0"),
            ("--expiry-delete-rate", "-1"),
            ("--expiry-delete-rate", "18446744073709551616"),
            ("--expiry-startup-grace-seconds", "-1"),
            ("--expiry-startup-grace-seconds", "18446744073709551616"),
            ("--expiry-bulk-fraction", "0"),
            ("--expiry-bulk-fraction", "-0.1"),
            ("--expiry-bulk-fraction", "1.01"),
            ("--expiry-bulk-fraction", "NaN"),
            ("--expiry-bulk-fraction", "inf"),
            ("--expiry-bulk-fraction", "1e-1"),
            ("--expiry-bulk-fraction", "0."),
            ("--expiry-bulk-fraction", ".1"),
            ("--expiry-bulk-fraction", "0.0000000000000000001"),
            ("--expiry-clock-jump-seconds", "0"),
            ("--expiry-clock-jump-seconds", "-1"),
            ("--expiry-clock-jump-seconds", "18446744073709551616"),
        ] {
            let error = config.set_cli_value(flag, value).unwrap_err();
            assert!(error.starts_with(flag), "{error}");
        }
    }

    #[test]
    fn scanner_config_repeated_flags_use_the_last_value() {
        let mut config = ExpirationScannerConfig::default();
        config.set_cli_value("--expiry-scan-rate", "1").unwrap();
        config.set_cli_value("--expiry-scan-rate", "2").unwrap();
        config
            .set_cli_value("--expiry-reaper-mode", "observe")
            .unwrap();
        config.set_cli_value("--expiry-reaper-mode", "off").unwrap();
        assert_eq!(config.scan_rate_candidates_per_second(), 2);
        assert_eq!(config.mode(), ExpirationReaperMode::Off);
    }

    #[test]
    fn bulk_fraction_parser_is_exact_bounded_decimal_and_last_value_wins() {
        for (input, expected) in [
            (
                "0.1",
                BulkFraction {
                    numerator: 1,
                    denominator: 10,
                },
            ),
            (
                "0.333",
                BulkFraction {
                    numerator: 333,
                    denominator: 1_000,
                },
            ),
            (
                "1.0",
                BulkFraction {
                    numerator: 1,
                    denominator: 1,
                },
            ),
            (
                "0.000000000000000001",
                BulkFraction {
                    numerator: 1,
                    denominator: 1_000_000_000_000_000_000,
                },
            ),
        ] {
            assert_eq!(
                parse_bulk_fraction("--expiry-bulk-fraction", input).unwrap(),
                expected,
                "{input}"
            );
        }

        let mut config = ExpirationScannerConfig::default();
        config
            .set_cli_value("--expiry-bulk-fraction", "0.1")
            .unwrap();
        config
            .set_cli_value("--expiry-bulk-fraction", "0.333")
            .unwrap();
        assert_eq!(
            config.bulk_fraction,
            BulkFraction {
                numerator: 333,
                denominator: 1_000,
            }
        );
        assert!((config.bulk_fraction() - 0.333).abs() < f64::EPSILON);
    }

    #[test]
    fn delete_mode_rejects_every_enabled_tier_before_runtime_startup() {
        let tier = |kind| TierConfig {
            kind,
            ..TierConfig::default()
        };
        for mode in [ExpirationReaperMode::Off, ExpirationReaperMode::Observe] {
            for kind in [TierKind::Off, TierKind::Local, TierKind::S3] {
                assert!(scanner_config(mode).validate_tier(&tier(kind)).is_ok());
            }
        }
        assert!(scanner_config(ExpirationReaperMode::Delete)
            .validate_tier(&tier(TierKind::Off))
            .is_ok());
        for kind in [TierKind::Local, TierKind::S3] {
            let error = scanner_config(ExpirationReaperMode::Delete)
                .validate_tier(&tier(kind))
                .unwrap_err();
            assert!(error.contains("--expiry-reaper-mode delete"));
            assert!(error.contains("--tier off"));
            assert!(error.contains(&format!("{kind:?}")));
        }
    }

    fn config() -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: Some(60),
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn scanner_config(mode: ExpirationReaperMode) -> ExpirationScannerConfig {
        ExpirationScannerConfig {
            mode,
            ..ExpirationScannerConfig::default()
        }
    }

    fn delete_safety_config(
        startup_grace_duration: Duration,
        bulk_fraction: &str,
        clock_jump_threshold_duration: Duration,
    ) -> ExpirationScannerConfig {
        ExpirationScannerConfig {
            mode: ExpirationReaperMode::Delete,
            startup_grace_duration,
            bulk_fraction: parse_bulk_fraction("--expiry-bulk-fraction", bulk_fraction).unwrap(),
            clock_jump_threshold_duration,
            ..ExpirationScannerConfig::default()
        }
    }

    #[test]
    fn delete_safety_requires_grace_and_an_observe_pass_including_empty() {
        let start = Instant::now();
        let status = ExpirationScannerStatus::new_at(
            &delete_safety_config(Duration::from_secs(5), "1.0", Duration::from_secs(5)),
            start,
        );
        assert_eq!(
            status.safety_snapshot_at(start),
            DeleteSafetySnapshot {
                initial_observe_pass_complete: false,
                startup_grace_elapsed: false,
                deletion_eligible: false,
                ..DeleteSafetySnapshot::default()
            }
        );
        status.record_observe_page(0, 0, true);
        let before_grace =
            status.safety_snapshot_at(start.checked_add(Duration::from_secs(4)).unwrap());
        assert!(before_grace.initial_observe_pass_complete);
        assert!(!before_grace.startup_grace_elapsed);
        assert!(!before_grace.deletion_eligible);
        let at_grace =
            status.safety_snapshot_at(start.checked_add(Duration::from_secs(5)).unwrap());
        assert!(at_grace.startup_grace_elapsed);
        assert!(at_grace.deletion_eligible);
        assert_eq!(at_grace.completed_checked, 0);
        assert_eq!(at_grace.completed_due_fraction(), 0.0);

        let zero_grace = ExpirationScannerStatus::new_at(
            &delete_safety_config(Duration::ZERO, "1.0", Duration::from_secs(5)),
            start,
        );
        assert!(zero_grace.safety_snapshot_at(start).startup_grace_elapsed);
        assert!(!zero_grace.safety_snapshot_at(start).deletion_eligible);
        zero_grace.record_observe_page(0, 0, true);
        assert!(zero_grace.safety_snapshot_at(start).deletion_eligible);
    }

    #[test]
    fn delete_safety_bulk_guard_is_strict_cumulative_and_sticky() {
        let start = Instant::now();
        let status = ExpirationScannerStatus::new_at(
            &delete_safety_config(Duration::ZERO, "0.25", Duration::from_secs(5)),
            start,
        );
        status.record_observe_page(4, 1, false);
        let partial = status.safety_snapshot_at(start);
        assert_eq!((partial.current_checked, partial.current_due), (4, 1));
        assert!(!partial.bulk_paused, "the exact threshold is allowed");
        status.record_observe_page(4, 1, true);
        let completed = status.safety_snapshot_at(start);
        assert_eq!(
            (completed.completed_checked, completed.completed_due),
            (8, 2)
        );
        assert_eq!((completed.current_checked, completed.current_due), (0, 0));
        assert_eq!(completed.completed_due_fraction(), 0.25);
        assert!(completed.deletion_eligible);

        // This page crosses the strict threshold before any future activation
        // could inspect an action token.
        status.record_observe_page(4, 2, false);
        let paused = status.safety_snapshot_at(start);
        assert!(paused.bulk_paused);
        assert!(!paused.deletion_eligible);
        status.record_observe_page(1, 0, true);
        let sticky = status.safety_snapshot_at(start);
        assert!(sticky.bulk_paused);
        assert_eq!((sticky.completed_checked, sticky.completed_due), (5, 2));
    }

    #[test]
    fn bulk_guard_compares_operator_decimals_exactly_without_u64_overflow() {
        let tenth = parse_bulk_fraction("--expiry-bulk-fraction", "0.1").unwrap();
        assert!(!tenth.exceeded_by(1, 10));
        assert!(tenth.exceeded_by(2, 10));

        // This is an exact large-scale tenth: `checked` is divisible by ten,
        // while one extra due candidate crosses it. Both cross-products still
        // fit the documented u128 proof.
        let checked = (u64::MAX / 10) * 10;
        assert!(!tenth.exceeded_by(checked / 10, checked));
        assert!(tenth.exceeded_by(checked / 10 + 1, checked));

        let thirds = parse_bulk_fraction("--expiry-bulk-fraction", "0.333").unwrap();
        assert!(!thirds.exceeded_by(333, 1_000));
        assert!(thirds.exceeded_by(334, 1_000));

        let whole = parse_bulk_fraction("--expiry-bulk-fraction", "1.0").unwrap();
        assert!(!whole.exceeded_by(u64::MAX, u64::MAX));

        let smallest =
            parse_bulk_fraction("--expiry-bulk-fraction", "0.000000000000000001").unwrap();
        assert!(!smallest.exceeded_by(1, 1_000_000_000_000_000_000));
        assert!(smallest.exceeded_by(2, 1_000_000_000_000_000_000));
    }

    #[test]
    fn delete_safety_counts_saturate_and_reset_only_after_completion() {
        let start = Instant::now();
        let status = ExpirationScannerStatus::new_at(
            &delete_safety_config(Duration::ZERO, "1.0", Duration::from_secs(5)),
            start,
        );
        status.record_observe_page(u64::MAX, 0, false);
        status.record_observe_page(1, 0, false);
        let saturated = status.safety_snapshot_at(start);
        assert_eq!(saturated.current_checked, u64::MAX);
        assert_eq!(saturated.current_due, 0);
        assert_eq!(saturated.current_due_fraction(), 0.0);
        status.record_observe_page(0, 0, true);
        let completed = status.safety_snapshot_at(start);
        assert_eq!(completed.completed_checked, u64::MAX);
        assert_eq!(completed.current_checked, 0);
    }

    #[test]
    fn delete_safety_clock_guard_handles_threshold_forward_backward_and_monotonic_anomaly() {
        let start = Instant::now();
        let config = delete_safety_config(Duration::ZERO, "1.0", Duration::from_secs(5));

        let threshold = ExpirationScannerStatus::new_at(&config, start);
        threshold.record_observe_page(0, 0, true);
        threshold.sample_clock(UNIX_EPOCH, start);
        threshold.sample_clock(UNIX_EPOCH + Duration::from_secs(5), start);
        assert!(!threshold.safety_snapshot_at(start).clock_paused);

        let forward = ExpirationScannerStatus::new_at(&config, start);
        forward.record_observe_page(0, 0, true);
        forward.sample_clock(UNIX_EPOCH, start);
        forward.sample_clock(UNIX_EPOCH + Duration::from_secs(6), start);
        assert!(forward.safety_snapshot_at(start).clock_paused);

        let backward = ExpirationScannerStatus::new_at(&config, start);
        backward.sample_clock(UNIX_EPOCH + Duration::from_secs(10), start);
        backward.sample_clock(
            UNIX_EPOCH + Duration::from_secs(9),
            start.checked_add(Duration::from_secs(1)).unwrap(),
        );
        assert!(backward.safety_snapshot_at(start).clock_paused);

        let reversed_monotonic = ExpirationScannerStatus::new_at(&config, start);
        reversed_monotonic.sample_clock(UNIX_EPOCH, start);
        reversed_monotonic.sample_clock(
            UNIX_EPOCH + Duration::from_secs(1),
            start.checked_sub(Duration::from_secs(1)).unwrap(),
        );
        assert!(reversed_monotonic.safety_snapshot_at(start).clock_paused);
    }

    #[test]
    fn scanner_snapshot_is_bounded_consistent_and_tracks_page_completion() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ExpirationScannerSnapshot>();
        assert_copy::<ExpirationOutcomeCounts>();

        let start = Instant::now();
        let wall = UNIX_EPOCH.checked_add(Duration::from_secs(10)).unwrap();
        let status =
            ExpirationScannerStatus::new_at(&scanner_config(ExpirationReaperMode::Observe), start);
        status.set_running(true);
        status.record_scanned_page(ScannerPageAccounting {
            checked: 3,
            due: 1,
            stale: 1,
            index_entry_count: 7,
            last_scanned_stream_id: Some(41),
            cursor_wrapped: false,
            pass_complete: false,
            latest_due_lag: Some(Duration::from_secs(2)),
            max_due_lag: Some(Duration::from_secs(2)),
            wall,
            monotonic: start,
        });
        let partial = status.snapshot_at(start);
        assert_eq!(partial.requested_mode, ExpirationReaperMode::Observe);
        assert_eq!(
            partial.effective_mode,
            ExpirationScannerEffectiveMode::Observe
        );
        assert!(partial.running);
        assert_eq!(partial.index_entry_count, 7);
        assert_eq!(partial.current_page_count, 1);
        assert_eq!(partial.last_scanned_stream_id, Some(41));
        assert_eq!((partial.current_checked, partial.current_due), (3, 1));
        assert_eq!((partial.total_checked, partial.total_due), (3, 1));
        assert_eq!(partial.outcomes.observed, 3);
        assert_eq!(partial.outcomes.stale, 1);
        assert_eq!(partial.latest_due_lag, Some(Duration::from_secs(2)));

        status.record_scanned_page(ScannerPageAccounting {
            checked: 2,
            due: 1,
            stale: 0,
            index_entry_count: 7,
            last_scanned_stream_id: Some(42),
            cursor_wrapped: true,
            pass_complete: true,
            latest_due_lag: Some(Duration::from_secs(4)),
            max_due_lag: Some(Duration::from_secs(4)),
            wall: wall.checked_add(Duration::from_secs(5)).unwrap(),
            monotonic: start.checked_add(Duration::from_secs(5)).unwrap(),
        });
        let completed = status.snapshot_at(start);
        assert!(completed.initial_observe_pass_complete);
        assert_eq!(
            (completed.completed_checked, completed.completed_due),
            (5, 2)
        );
        assert_eq!((completed.current_checked, completed.current_due), (0, 0));
        assert_eq!(completed.total_pages, 2);
        assert_eq!(completed.total_passes, 1);
        assert_eq!(completed.last_scanned_stream_id, Some(42));
        assert!(completed.cursor_wrapped);
        assert_eq!(
            completed.completed_max_due_lag,
            Some(Duration::from_secs(4))
        );
        assert_eq!(
            completed.last_completed_pass_duration,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            completed.last_completed_pass_wall_time,
            Some(wall.checked_add(Duration::from_secs(5)).unwrap())
        );
    }

    #[test]
    fn scanner_snapshot_saturates_and_concurrent_reads_are_self_consistent() {
        let start = Instant::now();
        let status = Arc::new(ExpirationScannerStatus::new_at(
            &scanner_config(ExpirationReaperMode::Observe),
            start,
        ));
        status.record_scanned_page(ScannerPageAccounting {
            checked: u64::MAX,
            due: u64::MAX,
            stale: 0,
            index_entry_count: 1,
            last_scanned_stream_id: None,
            cursor_wrapped: false,
            pass_complete: false,
            latest_due_lag: None,
            max_due_lag: None,
            wall: UNIX_EPOCH,
            monotonic: start,
        });
        let writer = Arc::clone(&status);
        let writer = std::thread::spawn(move || {
            for _ in 0..32 {
                writer.record_scanned_page(ScannerPageAccounting {
                    checked: 1,
                    due: 1,
                    stale: 0,
                    index_entry_count: 1,
                    last_scanned_stream_id: None,
                    cursor_wrapped: false,
                    pass_complete: false,
                    latest_due_lag: None,
                    max_due_lag: None,
                    wall: UNIX_EPOCH,
                    monotonic: Instant::now(),
                });
            }
        });
        for _ in 0..32 {
            let snapshot = status.snapshot_at(start);
            assert!(snapshot.current_due <= snapshot.current_checked);
            assert!(snapshot.total_due <= snapshot.total_checked);
            assert!(snapshot.total_pages >= snapshot.total_passes);
        }
        writer.join().unwrap();
        let saturated = status.snapshot_at(start);
        assert_eq!(saturated.total_checked, u64::MAX);
        assert_eq!(saturated.total_due, u64::MAX);
    }

    #[test]
    fn due_observation_reports_canonical_lag_without_wall_clock_panics() {
        let (directory, store) = store("snapshot-due-lag");
        let stream = streams(&store, &["due"]).pop().unwrap();
        stream.shared.write().unwrap().last_access = UNIX_EPOCH;
        let candidate = store
            .expiration_page(ExpirationCursor::start(), 1)
            .candidates
            .pop()
            .unwrap();
        assert!(matches!(
            store.observe_expiration_candidate(&candidate, UNIX_EPOCH + Duration::from_secs(61)),
            ExpirationCandidateObservation::Due { lag } if lag == Duration::from_secs(1)
        ));
        stream.shared.write().unwrap().last_access =
            UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            store.observe_expiration_candidate(&candidate, UNIX_EPOCH + Duration::from_secs(60)),
            ExpirationCandidateObservation::Due { lag } if lag == Duration::from_secs(1)
        ));
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    async fn wait_for_initial_pass(scanner: &ExpirationScanner) {
        tokio::time::timeout(
            Duration::from_secs(5),
            scanner.status().wait_initial_observe_pass(),
        )
        .await
        .expect("scanner should complete an observe pass within five seconds");
    }

    #[tokio::test]
    async fn scanner_off_starts_no_task_or_scan_loop() {
        let (directory, store) = store("scanner-off");
        let stream = streams(&store, &["due"]).pop().unwrap();
        stream.shared.write().unwrap().last_access = UNIX_EPOCH;

        let scanner = ExpirationScanner::start(&store, scanner_config(ExpirationReaperMode::Off));
        assert!(scanner.task.is_none());
        assert!(scanner.status().initial_observe_pass_complete());
        assert!(scanner.status().startup_grace_active_at(Instant::now()));
        let snapshot = scanner.snapshot_at(Instant::now());
        assert_eq!(snapshot.requested_mode, ExpirationReaperMode::Off);
        assert_eq!(snapshot.effective_mode, ExpirationScannerEffectiveMode::Off);
        assert!(!snapshot.running);
        assert!(snapshot.initial_observe_pass_complete);
        assert_eq!(snapshot.total_pages, 0);
        assert_eq!(
            snapshot.index_entry_count, 0,
            "Off has not observed the index"
        );
        wait_for_initial_pass(&scanner).await;
        scanner.shutdown().await;

        assert!(store
            .registered_stream("due")
            .is_some_and(|current| Arc::ptr_eq(&current, &stream)));
        assert!(!stream.fenced.load(Ordering::Acquire));
        assert_eq!(stream.shared.read().unwrap().last_access, UNIX_EPOCH);
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn scanner_observe_completes_empty_and_populated_passes_read_only() {
        let (empty_directory, empty_store) = store("scanner-empty");
        let empty =
            ExpirationScanner::start(&empty_store, scanner_config(ExpirationReaperMode::Observe));
        wait_for_initial_pass(&empty).await;
        let empty_snapshot = empty.snapshot_at(Instant::now());
        assert_eq!(
            empty_snapshot.effective_mode,
            ExpirationScannerEffectiveMode::Observe
        );
        assert!(empty_snapshot.running);
        assert!(empty_snapshot.initial_observe_pass_complete);
        assert_eq!(empty_snapshot.index_entry_count, 0);
        assert!(empty_snapshot.total_passes >= 1);
        empty.shutdown().await;
        drop(empty_store);
        let _ = std::fs::remove_dir_all(empty_directory);

        let (directory, store) = store("scanner-observe");
        let stream = streams(&store, &["due"]).pop().unwrap();
        stream.shared.write().unwrap().last_access = UNIX_EPOCH;
        let observed = observe_page(
            &store,
            ExpirationCursor::start(),
            UNIX_EPOCH + Duration::from_secs(61),
        );
        assert_eq!(observed.due_count, 1);
        assert!(observed.pass_complete);
        assert!(!stream.fenced.load(Ordering::Acquire));
        assert!(!stream.meta_dirty.load(Ordering::Acquire));
        assert_eq!(stream.shared.read().unwrap().last_access, UNIX_EPOCH);

        let scanner =
            ExpirationScanner::start(&store, scanner_config(ExpirationReaperMode::Observe));
        wait_for_initial_pass(&scanner).await;
        scanner.shutdown().await;
        assert!(store
            .registered_stream("due")
            .is_some_and(|current| Arc::ptr_eq(&current, &stream)));
        assert!(!stream.fenced.load(Ordering::Acquire));
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn delete_activation_keeps_the_first_pass_read_only_then_uses_bounded_retirement() {
        let (directory, store) = store("scanner-delete-activation");
        store.init_retirement_executor().unwrap();
        let stream = streams(&store, &["due"]).pop().unwrap();
        stream.shared.write().unwrap().last_access = UNIX_EPOCH;
        let config = delete_safety_config(Duration::ZERO, "1.0", Duration::from_secs(5));
        let status = ExpirationScannerStatus::new_at(&config, Instant::now());
        status.record_observe_page(1, 1, true);
        let safety = status.safety_snapshot_at(Instant::now());
        assert!(safety.deletion_eligible);
        let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        let mut pacer = DeletePacer::new(config.delete_rate_deletions_per_second());

        // The page which completed the initial pass cannot act, even though
        // publishing it made the next pass eligible.
        assert!(
            admit_due_candidates(
                &store,
                &status,
                &mut pacer,
                &mut shutdown,
                DeletePageDecision {
                    mode: config.mode(),
                    initial_pass_complete_at_page_start: false,
                    safety,
                },
                vec![Arc::clone(&stream)],
            )
            .await
        );
        assert_eq!(status.proactive_admission_attempts(), 0);
        assert!(!stream.fenced.load(Ordering::Acquire));

        assert!(
            admit_due_candidates(
                &store,
                &status,
                &mut pacer,
                &mut shutdown,
                DeletePageDecision {
                    mode: config.mode(),
                    initial_pass_complete_at_page_start: true,
                    safety,
                },
                vec![Arc::clone(&stream)],
            )
            .await
        );
        assert_eq!(status.proactive_admission_attempts(), 1);
        assert!(stream.fenced.load(Ordering::Acquire));
        let snapshot = status.snapshot_at(Instant::now());
        assert_eq!(snapshot.proactive_admission_attempts, 1);
        assert_eq!(snapshot.outcomes.reaped, 0);
        assert_eq!(snapshot.outcomes.failed, 0);
        store.retirement_executor().unwrap().shutdown().await;

        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn scanner_outcomes_keep_renewal_distinct_from_logical_admission_and_failure() {
        let (directory, store) = store("scanner-renewed-outcome");
        let stream = streams(&store, &["due"]).pop().unwrap();
        let status = ExpirationScannerStatus::new_at(
            &scanner_config(ExpirationReaperMode::Delete),
            Instant::now(),
        );
        status.record_proactive_outcome(&crate::store::ExplicitRetirementResult::Renewed(
            crate::retirement::RetirementTicket::new(),
        ));
        status.record_proactive_outcome(&crate::store::ExplicitRetirementResult::Owner(
            crate::retirement::RetirementTicket::new(),
        ));
        status.record_proactive_outcome(&crate::store::ExplicitRetirementResult::Cancelled(
            crate::retirement::RetirementTicket::new(),
        ));
        status.record_proactive_outcome(&crate::store::ExplicitRetirementResult::Stale);
        let outcomes = status.snapshot_at(Instant::now()).outcomes;
        assert_eq!(outcomes.renewed, 1);
        assert_eq!(
            outcomes.reaped, 0,
            "logical ownership is not physical reaping"
        );
        assert_eq!(outcomes.fenced, 0, "duplicate tickets do not re-fence");
        assert_eq!(
            outcomes.failed, 1,
            "identity-loss cancellation is not renewal"
        );
        assert_eq!(outcomes.stale, 1, "replacement identity loss is distinct");
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn delete_activation_safety_gates_and_observer_modes_admit_nothing() {
        let (directory, store) = store("scanner-delete-gates");
        let stream = streams(&store, &["due"]).pop().unwrap();
        stream.shared.write().unwrap().last_access = UNIX_EPOCH;
        let config = delete_safety_config(Duration::ZERO, "0.25", Duration::from_secs(5));
        let status = ExpirationScannerStatus::new_at(&config, Instant::now());
        status.record_observe_page(4, 2, true);
        let bulk_paused = status.safety_snapshot_at(Instant::now());
        assert!(bulk_paused.bulk_paused);
        let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        let mut pacer = DeletePacer::new(config.delete_rate_deletions_per_second());
        assert!(
            admit_due_candidates(
                &store,
                &status,
                &mut pacer,
                &mut shutdown,
                DeletePageDecision {
                    mode: ExpirationReaperMode::Delete,
                    initial_pass_complete_at_page_start: true,
                    safety: bulk_paused,
                },
                vec![Arc::clone(&stream)],
            )
            .await
        );
        assert_eq!(status.proactive_admission_attempts(), 0);

        assert!(
            admit_due_candidates(
                &store,
                &status,
                &mut pacer,
                &mut shutdown,
                DeletePageDecision {
                    mode: ExpirationReaperMode::Delete,
                    initial_pass_complete_at_page_start: true,
                    safety: DeleteSafetySnapshot::default(),
                },
                vec![Arc::clone(&stream)],
            )
            .await
        );

        let clock_status = ExpirationScannerStatus::new_at(&config, Instant::now());
        clock_status.record_observe_page(1, 1, true);
        let now = Instant::now();
        clock_status.sample_clock(UNIX_EPOCH + Duration::from_secs(1), now);
        clock_status.sample_clock(UNIX_EPOCH, now.checked_add(Duration::from_secs(1)).unwrap());
        let clock_paused = clock_status.safety_snapshot_at(Instant::now());
        assert!(clock_paused.clock_paused);
        assert!(
            admit_due_candidates(
                &store,
                &clock_status,
                &mut pacer,
                &mut shutdown,
                DeletePageDecision {
                    mode: ExpirationReaperMode::Delete,
                    initial_pass_complete_at_page_start: true,
                    safety: clock_paused,
                },
                vec![Arc::clone(&stream)],
            )
            .await
        );
        for mode in [ExpirationReaperMode::Off, ExpirationReaperMode::Observe] {
            assert!(
                admit_due_candidates(
                    &store,
                    &status,
                    &mut pacer,
                    &mut shutdown,
                    DeletePageDecision {
                        mode,
                        initial_pass_complete_at_page_start: true,
                        safety: DeleteSafetySnapshot {
                            deletion_eligible: true,
                            ..DeleteSafetySnapshot::default()
                        },
                    },
                    vec![Arc::clone(&stream)],
                )
                .await
            );
        }
        assert!(!stream.fenced.load(Ordering::Acquire));
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn delete_admission_counts_rejections_and_pacing_shutdown_is_prompt() {
        let (directory, store) = store("scanner-delete-rejected");
        let streams = streams(&store, &["first", "second"]);
        for stream in &streams {
            stream.shared.write().unwrap().last_access = UNIX_EPOCH;
        }
        let config = delete_safety_config(Duration::ZERO, "1.0", Duration::from_secs(5));
        let status = ExpirationScannerStatus::new_at(&config, Instant::now());
        status.record_observe_page(2, 2, true);
        let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        let mut immediate_pacer = DeletePacer::new(1_000_000_000);
        assert!(
            admit_due_candidates(
                &store,
                &status,
                &mut immediate_pacer,
                &mut shutdown,
                DeletePageDecision {
                    mode: ExpirationReaperMode::Delete,
                    initial_pass_complete_at_page_start: true,
                    safety: status.safety_snapshot_at(Instant::now()),
                },
                streams.clone(),
            )
            .await
        );
        assert_eq!(status.proactive_admission_attempts(), 2);
        assert_eq!(status.snapshot_at(Instant::now()).outcomes.failed, 2);
        assert!(streams
            .iter()
            .all(|stream| !stream.fenced.load(Ordering::Acquire)));

        let (shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        let mut paced = DeletePacer::new(1);
        paced.next_permit = Some(Instant::now().checked_add(Duration::from_secs(1)).unwrap());
        assert!(shutdown_tx.send(true).is_ok());
        assert!(!tokio::time::timeout(
            Duration::from_secs(1),
            paced.wait_for_permit(&mut shutdown)
        )
        .await
        .expect("shutdown must interrupt delete pacing"));

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn delete_pacing_is_independent_nonzero_and_rate_bounded() {
        assert_eq!(delete_pacing_interval(100), Duration::from_millis(10));
        assert_eq!(
            delete_pacing_interval(1_000_000_000),
            Duration::from_nanos(1)
        );
    }

    #[test]
    fn scanner_prunes_dead_and_replaced_candidates_without_touching_replacements() {
        let (directory, store) = store("scanner-stale");
        let dead = streams(&store, &["dead"]).pop().unwrap();
        assert!(store.streams.remove("dead").is_some());
        drop(dead);
        let observed = observe_page(&store, ExpirationCursor::start(), SystemTime::now());
        assert_eq!(observed.candidate_count, 1);
        assert_eq!(
            store
                .expiration_page(ExpirationCursor::start(), 1)
                .candidates
                .len(),
            0
        );

        let old = streams(&store, &["replacement"]).pop().unwrap();
        assert!(store.streams.remove("replacement").is_some());
        let replacement = match store.create("replacement", config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("vacated path must create a replacement"),
        };
        assert!(!Arc::ptr_eq(&old, &replacement));
        let observed = observe_page(&store, ExpirationCursor::start(), SystemTime::now());
        assert_eq!(observed.candidate_count, 2);
        let page = store.expiration_page(ExpirationCursor::start(), 2);
        assert_eq!(page.candidates.len(), 1);
        assert_eq!(page.candidates[0].stream_id, replacement.id);
        assert!(page.candidates[0]
            .stream
            .upgrade()
            .is_some_and(|current| Arc::ptr_eq(&current, &replacement)));

        drop(old);
        drop(replacement);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn scanner_page_pacing_is_nonzero_and_rate_bounded() {
        assert_eq!(page_pacing_delay(10_000, 1), Duration::from_micros(100));
        assert_eq!(
            page_pacing_delay(10_000, 128),
            Duration::from_micros(12_800)
        );
        assert_eq!(page_pacing_delay(1_000_000_000, 1), Duration::from_nanos(1));
        assert_eq!(page_pacing_delay(10_000, 0), IDLE_SCAN_DELAY);
    }

    #[tokio::test]
    async fn scanner_shutdown_joins_the_supervised_task() {
        let (directory, store) = store("scanner-shutdown");
        let scanner =
            ExpirationScanner::start(&store, scanner_config(ExpirationReaperMode::Observe));
        let status = Arc::clone(scanner.status());
        assert!(status.snapshot_at(Instant::now()).running);
        tokio::time::timeout(Duration::from_secs(5), scanner.shutdown())
            .await
            .expect("scanner shutdown should join promptly");
        let snapshot = status.snapshot_at(Instant::now());
        assert!(!snapshot.running);
        assert_eq!(
            snapshot.total_passes, 0,
            "shutdown may leave a partial pass"
        );
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    fn store(tag: &str) -> (std::path::PathBuf, Arc<Store>) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ds-expiration-index-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        (directory, store)
    }

    fn streams(store: &Store, paths: &[&str]) -> Vec<Arc<StreamState>> {
        paths
            .iter()
            .map(
                |path| match store.create(path, config(), None, 0).unwrap() {
                    CreateResult::Created(stream) => stream,
                    _ => panic!("test stream path must be vacant"),
                },
            )
            .collect()
    }

    fn ids(page: &ExpirationPage) -> Vec<u64> {
        page.candidates
            .iter()
            .map(|candidate| candidate.stream_id)
            .collect()
    }

    #[derive(Debug, Default, PartialEq, Eq)]
    struct IndexPassDiagnostics {
        pages: usize,
        completed_passes: usize,
        candidates: usize,
        pruned_dead: usize,
        wrapped_pages: usize,
        max_page_candidates: usize,
        max_page_capacity: usize,
    }

    /// Drive the production index's actual bounded page/cursor/prune loop.
    /// No shadow `Vec` or alternate priority structure represents the index.
    fn scan_dead_index_pass(
        index: &ExpiringStreams,
        mut cursor: ExpirationCursor,
        page_size: usize,
    ) -> IndexPassDiagnostics {
        let mut diagnostics = IndexPassDiagnostics::default();
        loop {
            let page = index.page(cursor, page_size);
            diagnostics.pages += 1;
            diagnostics.candidates += page.candidates.len();
            diagnostics.max_page_candidates =
                diagnostics.max_page_candidates.max(page.candidates.len());
            diagnostics.max_page_capacity = diagnostics
                .max_page_capacity
                .max(page.candidates.capacity());
            if page.wrapped {
                diagnostics.wrapped_pages += 1;
            }
            for candidate in &page.candidates {
                assert!(
                    candidate.stream.upgrade().is_none(),
                    "qualification fixture holds no stream Arc in its scaled index"
                );
                assert!(
                    index.prune_dead(candidate),
                    "the current dead candidate is pruned by exact weak identity"
                );
                diagnostics.pruned_dead += 1;
            }
            if page.pass_complete {
                diagnostics.completed_passes += 1;
                assert_eq!(page.next_cursor, ExpirationCursor::start());
                return diagnostics;
            }
            cursor = page.next_cursor;
        }
    }

    /// Install a dead current occupant after proving that an older dead page
    /// candidate cannot remove either a live or a different dead replacement.
    fn install_replaced_dead_scale_entry(
        index: &ExpiringStreams,
        store: &Arc<Store>,
        stream_id: u64,
    ) {
        let old = streams(store, &["scale-old"]).pop().unwrap();
        index.register_replacement_for_test(stream_id, &old);
        let stale = index
            .page(ExpirationCursor::after(stream_id - 1), 1)
            .candidates
            .pop()
            .unwrap();
        assert_eq!(stale.stream_id, stream_id);
        assert!(store.streams.remove("scale-old").is_some());
        drop(old);

        let live_replacement = streams(store, &["scale-live-replacement"]).pop().unwrap();
        index.register_replacement_for_test(stream_id, &live_replacement);
        assert!(
            !index.prune_dead(&stale),
            "a stale dead candidate cannot prune its live replacement"
        );
        assert!(store.streams.remove("scale-live-replacement").is_some());
        drop(live_replacement);

        let dead_replacement = streams(store, &["scale-dead-replacement"]).pop().unwrap();
        index.register_replacement_for_test(stream_id, &dead_replacement);
        assert!(store.streams.remove("scale-dead-replacement").is_some());
        drop(dead_replacement);
        assert!(
            !index.prune_dead(&stale),
            "a stale dead candidate cannot prune a different dead replacement"
        );
    }

    fn assert_scale_pass(
        index: &ExpiringStreams,
        entry_count: usize,
        page_size: usize,
        anchor: u64,
        expected_wrapped_pages: usize,
    ) -> IndexPassDiagnostics {
        let diagnostics = scan_dead_index_pass(index, ExpirationCursor::after(anchor), page_size);
        assert_eq!(diagnostics.pages, entry_count / page_size);
        assert_eq!(diagnostics.completed_passes, 1);
        assert_eq!(diagnostics.candidates, entry_count);
        assert_eq!(diagnostics.pruned_dead, entry_count);
        assert_eq!(diagnostics.wrapped_pages, expected_wrapped_pages);
        assert!(diagnostics.max_page_candidates <= page_size);
        assert!(diagnostics.max_page_capacity <= page_size);
        assert_eq!(index.len(), 0, "one full pass prunes every dead entry");
        diagnostics
    }

    #[test]
    fn expiration_index_scale_twin_uses_bounded_pages_and_read_only_observe() {
        const ENTRY_COUNT: usize = 12;
        const PAGE_SIZE: usize = 3;
        const ANCHOR: u64 = 5;
        const REPLACED_ID: u64 = 6;

        let (directory, store) = store("scale-twin");
        let index = ExpiringStreams::default();
        index.seed_dead_range_for_test(0, ENTRY_COUNT);
        install_replaced_dead_scale_entry(&index, &store, REPLACED_ID);
        assert_eq!(index.len(), ENTRY_COUNT);
        let diagnostics = assert_scale_pass(&index, ENTRY_COUNT, PAGE_SIZE, ANCHOR, 2);
        assert_eq!(
            diagnostics,
            IndexPassDiagnostics {
                pages: 4,
                completed_passes: 1,
                candidates: 12,
                pruned_dead: 12,
                wrapped_pages: 2,
                max_page_candidates: 3,
                max_page_capacity: 3,
            }
        );

        // The production Observe path classifies a due stream but owns no
        // retirement callback. The stream remains registered and unfenced.
        let observed_stream = streams(&store, &["scale-observe"]).pop().unwrap();
        observed_stream.shared.write().unwrap().last_access = UNIX_EPOCH;
        let observed = observe_page(
            &store,
            ExpirationCursor::start(),
            UNIX_EPOCH + Duration::from_secs(61),
        );
        assert_eq!(observed.due_count, 1);
        assert_eq!(observed.due_streams.len(), 1);
        assert!(store
            .registered_stream("scale-observe")
            .is_some_and(|current| Arc::ptr_eq(&current, &observed_stream)));
        assert!(!observed_stream.fenced.load(Ordering::Acquire));
        assert!(!observed_stream.meta_dirty.load(Ordering::Acquire));
        drop(observed);

        // Off is a level-complete no-op: it starts no task and does not scan
        // or retire the observed identity.
        let off = ExpirationScanner::start(&store, scanner_config(ExpirationReaperMode::Off));
        assert!(off.task.is_none());
        let off_snapshot = off.snapshot_at(Instant::now());
        assert_eq!(off_snapshot.total_pages, 0);
        assert_eq!(off_snapshot.outcomes, ExpirationOutcomeCounts::default());
        drop(off);
        assert!(store
            .registered_stream("scale-observe")
            .is_some_and(|current| Arc::ptr_eq(&current, &observed_stream)));
        assert!(!observed_stream.fenced.load(Ordering::Acquire));

        drop(observed_stream);
        drop(index);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    #[ignore = "release-only one-million-entry expiration-index qualification"]
    fn expiration_index_one_million_entry_qualification() {
        const ENTRY_COUNT: usize = 1_000_000;
        const PAGE_SIZE: usize = 10_000;
        const ANCHOR: u64 = 499_999;
        const REPLACED_ID: u64 = 500_000;

        let (directory, store) = store("scale-million");
        let index = ExpiringStreams::default();
        index.seed_dead_range_for_test(0, ENTRY_COUNT);
        install_replaced_dead_scale_entry(&index, &store, REPLACED_ID);
        assert_eq!(index.len(), ENTRY_COUNT);

        let started = Instant::now();
        let diagnostics = assert_scale_pass(&index, ENTRY_COUNT, PAGE_SIZE, ANCHOR, 50);
        let elapsed = started.elapsed();
        eprintln!(
            "expiration-index qualification elapsed_ms={} entries={} pages={} candidates={} pruned_dead={} wrapped_pages={} max_page_candidates={} max_page_capacity={}",
            elapsed.as_millis(),
            ENTRY_COUNT,
            diagnostics.pages,
            diagnostics.candidates,
            diagnostics.pruned_dead,
            diagnostics.wrapped_pages,
            diagnostics.max_page_candidates,
            diagnostics.max_page_capacity,
        );

        drop(index);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn pages_are_sorted_bounded_and_complete_a_fresh_pass() {
        let (directory, store) = store("ordered");
        let streams = streams(&store, &["a", "b", "c"]);
        let index = ExpiringStreams::default();
        for stream in &streams {
            index.register_exact(stream);
            index.register_exact(stream);
        }
        let mut expected: Vec<_> = streams.iter().map(|stream| stream.id).collect();
        expected.sort_unstable();
        assert_eq!(index.len(), 3);

        let first = index.page(ExpirationCursor::start(), 2);
        assert_eq!(ids(&first), expected[..2]);
        assert_eq!(first.entry_count, 3);
        assert!(!first.wrapped);
        assert!(!first.pass_complete);
        let second = index.page(first.next_cursor, 2);
        assert_eq!(ids(&second), expected[2..]);
        assert_eq!(second.entry_count, 3);
        assert!(second.pass_complete);
        assert_eq!(second.next_cursor, ExpirationCursor::start());

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn cursor_wraps_once_without_duplicate_entries_at_u64_boundaries() {
        let (directory, store) = store("wrap");
        let streams = streams(&store, &["a", "b", "c"]);
        let index = ExpiringStreams::default();
        for stream in &streams {
            index.register_exact(stream);
        }
        let mut expected: Vec<_> = streams.iter().map(|stream| stream.id).collect();
        expected.sort_unstable();

        let middle = expected[1];
        let page = index.page(ExpirationCursor::after(middle), 10);
        assert_eq!(ids(&page), vec![expected[2], expected[0], expected[1]]);
        assert!(page.wrapped);
        assert!(page.pass_complete);
        let mut distinct = ids(&page);
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct, expected);

        let max = index.page(ExpirationCursor::after(u64::MAX), 10);
        assert_eq!(ids(&max), expected);
        assert!(max.wrapped);
        assert!(max.pass_complete);
        let zero = index.page(ExpirationCursor::after(0), 10);
        let mut expected_after_zero: Vec<_> = expected
            .iter()
            .copied()
            .filter(|stream_id| *stream_id > 0)
            .collect();
        expected_after_zero.extend(expected.iter().copied().filter(|stream_id| *stream_id == 0));
        assert_eq!(ids(&zero), expected_after_zero);
        assert!(
            zero.wrapped,
            "an anchored pass attempts its lower half once"
        );

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn wrapped_pass_continues_across_live_pages_without_revisiting_an_id() {
        let (directory, store) = store("live-wrap-pages");
        let streams = streams(&store, &["low", "middle", "first-high", "new-high"]);
        let mut ordered = streams.clone();
        ordered.sort_by_key(|stream| stream.id);
        let (low, middle, first_high, new_high) =
            (&ordered[0], &ordered[1], &ordered[2], &ordered[3]);
        let index = ExpiringStreams::default();
        index.register_exact(middle);
        index.register_exact(first_high);

        let first = index.page(ExpirationCursor::after(middle.id), 1);
        assert_eq!(ids(&first), vec![first_high.id]);
        assert!(!first.wrapped);
        assert!(!first.pass_complete);

        // Both insertions happen after the pass began. The new high identity is
        // still ahead of its live `after`, while the low identity belongs only
        // to the wrapped half.
        index.register_exact(new_high);
        index.register_exact(low);
        let second = index.page(first.next_cursor, 1);
        assert_eq!(ids(&second), vec![new_high.id]);
        assert!(!second.wrapped);
        assert!(!second.pass_complete);

        let third = index.page(second.next_cursor, 1);
        assert_eq!(ids(&third), vec![low.id]);
        assert!(third.wrapped, "the first lower-half page flips wrap state");
        assert!(!third.pass_complete);
        let fourth = index.page(third.next_cursor, 1);
        assert_eq!(ids(&fourth), vec![middle.id]);
        assert!(fourth.wrapped);
        assert!(fourth.pass_complete);
        assert_eq!(fourth.next_cursor, ExpirationCursor::start());

        let all = [
            ids(&first)[0],
            ids(&second)[0],
            ids(&third)[0],
            ids(&fourth)[0],
        ];
        assert_eq!(all, [first_high.id, new_high.id, low.id, middle.id]);
        let mut distinct = all.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), all.len());

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn zero_and_oversized_limits_have_defined_cursor_behavior() {
        let (directory, store) = store("limits");
        let streams = streams(&store, &["a", "b"]);
        let index = ExpiringStreams::default();
        for stream in &streams {
            index.register_exact(stream);
        }
        let cursor = ExpirationCursor::after(streams[0].id);
        let zero = index.page(cursor, 0);
        assert!(zero.candidates.is_empty());
        assert_eq!(zero.next_cursor, cursor);
        assert!(!zero.pass_complete);
        let all = index.page(ExpirationCursor::start(), usize::MAX);
        assert_eq!(all.candidates.len(), 2);
        assert!(all.pass_complete);

        let empty = ExpiringStreams::default().page(ExpirationCursor::after(u64::MAX), 0);
        assert!(empty.candidates.is_empty());
        assert!(empty.pass_complete);

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn deleted_cursor_and_inserts_on_both_sides_remain_ordered() {
        let (directory, store) = store("cursor-churn");
        let streams = streams(&store, &["a", "b", "c", "d"]);
        let mut ordered = streams.clone();
        ordered.sort_by_key(|stream| stream.id);
        let index = ExpiringStreams::default();
        index.register_exact(&ordered[0]);
        index.register_exact(&ordered[2]);
        let cursor_id = ordered[2].id;
        assert!(index.unregister_exact(&ordered[2]));
        index.register_exact(&ordered[1]); // inserted below the now-deleted cursor
        index.register_exact(&ordered[3]); // inserted above it

        let page = index.page(ExpirationCursor::after(cursor_id), 10);
        assert_eq!(
            ids(&page),
            vec![ordered[3].id, ordered[0].id, ordered[1].id]
        );
        assert!(page.wrapped);
        assert!(page.pass_complete);

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn live_same_id_replacement_is_registered_and_stale_unregistration_is_safe() {
        let (directory, store) = store("replacement");
        let streams = streams(&store, &["old", "replacement"]);
        let index = ExpiringStreams::default();
        index.register_exact(&streams[0]);
        // The test-only stable-ID injection calls the same register_at_id
        // implementation as register_exact; production IDs are immutable.
        index.register_replacement_for_test(streams[0].id, &streams[1]);

        assert!(!index.unregister_exact(&streams[0]));
        let page = index.page(ExpirationCursor::start(), 1);
        assert_eq!(page.candidates[0].stream_id, streams[0].id);
        assert!(page.candidates[0]
            .stream
            .upgrade()
            .is_some_and(|current| Arc::ptr_eq(&current, &streams[1])));

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn stale_dead_candidate_cannot_prune_live_or_dead_replacements() {
        let (directory, store) = store("stale-prune");
        let mut streams = streams(&store, &["old", "live", "dead"]);
        let dead = streams.pop().unwrap();
        let live = streams.pop().unwrap();
        let old = streams.pop().unwrap();
        let index = ExpiringStreams::default();
        index.register_exact(&old);
        let stale = index
            .page(ExpirationCursor::start(), 1)
            .candidates
            .remove(0);
        assert!(store.streams.remove("old").is_some());
        drop(old);
        assert!(stale.stream.upgrade().is_none());

        index.register_replacement_for_test(stale.stream_id, &live);
        assert!(
            !index.prune_dead(&stale),
            "a stale dead candidate cannot prune a live replacement"
        );
        let live_page = index.page(ExpirationCursor::start(), 1);
        assert!(live_page.candidates[0]
            .stream
            .upgrade()
            .is_some_and(|current| Arc::ptr_eq(&current, &live)));

        index.register_replacement_for_test(stale.stream_id, &dead);
        assert!(store.streams.remove("dead").is_some());
        drop(dead);
        assert!(
            !index.prune_dead(&stale),
            "a stale candidate cannot prune a different dead replacement"
        );
        assert_eq!(index.len(), 1);
        let dead_page = index.page(ExpirationCursor::start(), 1);
        assert!(dead_page.candidates[0].stream.upgrade().is_none());

        drop(live);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn dead_weak_candidates_never_retain_streams_and_prune_exactly() {
        let (directory, store) = store("dead");
        let stream = streams(&store, &["dead"]).pop().expect("one test stream");
        let index = ExpiringStreams::default();
        index.register_exact(&stream);
        assert!(store.streams.remove("dead").is_some());
        drop(stream);
        drop(store);

        let page = index.page(ExpirationCursor::start(), 1);
        assert!(page.candidates[0].stream.upgrade().is_none());
        assert!(index.prune_dead(&page.candidates[0]));
        assert_eq!(index.len(), 0);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn concurrent_register_remove_and_page_are_lock_safe() {
        let (directory, store) = store("concurrent");
        let streams = streams(&store, &["a", "b", "c", "d"]);
        let index = Arc::new(ExpiringStreams::default());
        std::thread::scope(|scope| {
            for stream in &streams {
                let index = Arc::clone(&index);
                scope.spawn(move || {
                    for _ in 0..100 {
                        index.register_exact(stream);
                        let _ = index.page(ExpirationCursor::after(stream.id), 2);
                        assert!(index.unregister_exact(stream));
                    }
                });
            }
        });
        assert_eq!(index.len(), 0);

        drop(streams);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }
}
