use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::store_manifest::StoreManifestV1;
use crate::wal::walset::WalSet;

const STARTING: u8 = 0;
const RECOVERING: u8 = 1;
const READY: u8 = 2;
const STOPPING: u8 = 3;

pub struct AdminReadiness {
    manifest: StoreManifestV1,
    artifact_digest: String,
    minimum_free_bytes: u64,
    minimum_free_inodes: u64,
    status: AtomicU8,
    wal: std::sync::OnceLock<Arc<WalSet>>,
    expiration_scanner: std::sync::OnceLock<Arc<crate::expiration::ExpirationScannerStatus>>,
}

#[derive(Serialize)]
struct ReadyResponse<'a> {
    contract_version: &'static str,
    status: &'static str,
    artifact_digest: &'a str,
    manifest: &'a StoreManifestV1,
    recovery: Recovery,
    reserve: Reserve,
}
#[derive(Serialize)]
struct Recovery {
    completed: bool,
    wal_shards: Vec<WalShard>,
}
#[derive(Serialize)]
struct WalShard {
    shard: u32,
    durable_lsn: u64,
    checkpoint_lsn: u64,
}
#[derive(Serialize)]
struct Reserve {
    free_bytes: u64,
    free_inodes: u64,
    minimum_free_bytes: u64,
    minimum_free_inodes: u64,
    satisfied: bool,
}

/// Versioned, bounded expiry-health response. Scanner and retirement snapshots
/// are captured sequentially, so each component is internally consistent but
/// the two components are not a single cross-component transaction.
#[derive(Serialize)]
struct ExpiryResponse {
    contract_version: &'static str,
    capture: ExpiryCapture,
    scanner: Option<ExpiryScanner>,
    retirement: Option<ExpiryRetirement>,
}

#[derive(Serialize)]
struct ExpiryCapture {
    consistency: &'static str,
    bounded: bool,
}

#[derive(Serialize)]
struct ExpiryScanner {
    requested_mode: &'static str,
    effective_mode: &'static str,
    running: bool,
    initial_observe_pass_complete: bool,
    startup_grace_elapsed: bool,
    deletion_eligible: bool,
    bulk_paused: bool,
    clock_paused: bool,
    cursor: ExpiryCursor,
    index_entries: usize,
    current: ExpiryCounts,
    completed: ExpiryCounts,
    totals: ExpiryTotals,
    bulk_threshold: ExpiryBulkThreshold,
    due_lag: ExpiryDueLag,
    clock_drift_ms: Option<u64>,
    admission_attempts: u64,
    outcomes: ExpiryOutcomes,
    last_scan_unix_ms: Option<i64>,
    last_completed_pass_unix_ms: Option<i64>,
    last_completed_pass_duration_ms: Option<u64>,
}

#[derive(Serialize)]
struct ExpiryCursor {
    pass_sequence: u64,
    current_page_count: u64,
    wrapped: bool,
}

#[derive(Serialize)]
struct ExpiryCounts {
    checked: u64,
    due: u64,
    due_fraction_display: String,
}

#[derive(Serialize)]
struct ExpiryTotals {
    checked: u64,
    due: u64,
    pages: u64,
    passes: u64,
}

#[derive(Serialize)]
struct ExpiryBulkThreshold {
    numerator: u64,
    denominator: u64,
}

#[derive(Serialize)]
struct ExpiryDueLag {
    latest_ms: Option<u64>,
    oldest_current_ms: Option<u64>,
    oldest_completed_ms: Option<u64>,
}

#[derive(Serialize)]
struct ExpiryOutcomes {
    observed: u64,
    renewed: u64,
    fenced: u64,
    soft_deleted: u64,
    reaped: u64,
    stale: u64,
    failed: u64,
}

#[derive(Serialize)]
struct ExpiryRetirement {
    capacities: RetirementCapacities,
    jobs: RetirementJobs,
    physical: RetirementPhysical,
    retries: RetirementRetries,
    outcomes: RetirementOutcomes,
    timing: RetirementTiming,
    reclaimed_local_bytes: u64,
    oldest_admission_age_ms: Option<u64>,
    closed: bool,
}

#[derive(Serialize)]
struct RetirementCapacities {
    queue: usize,
    coordinator: usize,
    proactive_coordinator: usize,
    interactive_coordinator_reserved: usize,
    physical_total: usize,
    interactive_physical: usize,
    proactive_physical: usize,
}

#[derive(Serialize)]
struct RetirementJobs {
    total: usize,
    interactive_pending: usize,
    proactive_pending: usize,
    interactive_active: usize,
    proactive_active: usize,
}

#[derive(Serialize)]
struct RetirementPhysical {
    interactive_queued: usize,
    proactive_queued: usize,
    interactive_active: usize,
    proactive_active: usize,
    workers_total: usize,
    workers_live: usize,
}

#[derive(Serialize)]
struct RetirementRetries {
    heap_count: usize,
    cumulative_attempts: u64,
    cleanup_failed_current: u64,
}

#[derive(Serialize)]
struct RetirementOutcomes {
    first_attempt: RetirementOutcomeCounts,
    terminal: RetirementOutcomeCounts,
}

#[derive(Serialize)]
struct RetirementOutcomeCounts {
    successes: u64,
    failures: u64,
    cancellations: u64,
}

#[derive(Serialize)]
struct RetirementTiming {
    latest_cleanup_unix_ms: Option<i64>,
    latest_cleanup_duration_ms: Option<u64>,
    last_successful_cleanup_unix_ms: Option<i64>,
    last_successful_cleanup_duration_ms: Option<u64>,
}

impl AdminReadiness {
    pub fn new(
        manifest: StoreManifestV1,
        artifact_digest: String,
        minimum_free_bytes: u64,
        minimum_free_inodes: u64,
    ) -> Self {
        Self {
            manifest,
            artifact_digest,
            minimum_free_bytes,
            minimum_free_inodes,
            status: AtomicU8::new(STARTING),
            wal: std::sync::OnceLock::new(),
            expiration_scanner: std::sync::OnceLock::new(),
        }
    }
    pub fn attach_wal(&self, wal: Arc<WalSet>) {
        let _ = self.wal.set(wal);
    }
    pub fn attach_expiration_scanner(
        &self,
        scanner: Arc<crate::expiration::ExpirationScannerStatus>,
    ) {
        let _ = self.expiration_scanner.set(scanner);
    }
    pub fn recovering(&self) {
        self.status.store(RECOVERING, Ordering::Release);
    }
    pub fn ready(&self) {
        self.status.store(READY, Ordering::Release);
    }
    pub fn stopping(&self) {
        self.status.store(STOPPING, Ordering::Release);
    }
    pub fn json(&self, data_dir: &std::path::Path) -> (u16, Vec<u8>) {
        let status = self.status.load(Ordering::Acquire);
        let (free_bytes, free_inodes) = filesystem_free(data_dir).unwrap_or((0, 0));
        let reserve_ok =
            free_bytes >= self.minimum_free_bytes && free_inodes >= self.minimum_free_inodes;
        let state = match status {
            STARTING => "starting",
            RECOVERING => "recovering",
            // Storage pressure is not a ready state even though replay itself
            // completed. Keep it non-ready until the configured reserve returns.
            READY if !reserve_ok => "starting",
            READY => "ready",
            _ => "stopping",
        };
        let completed = status == READY;
        let wal_shards = self
            .wal
            .get()
            .map(|w| {
                w.shards()
                    .iter()
                    .enumerate()
                    .map(|(i, shard)| WalShard {
                        shard: i as u32,
                        durable_lsn: shard.durable_lsn_now(),
                        checkpoint_lsn: shard.read_checkpoint_lsn(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let body = serde_json::to_vec(&ReadyResponse {
            contract_version: "durable-streams-store-ready-v1",
            status: state,
            artifact_digest: &self.artifact_digest,
            manifest: &self.manifest,
            recovery: Recovery {
                completed,
                wal_shards,
            },
            reserve: Reserve {
                free_bytes,
                free_inodes,
                minimum_free_bytes: self.minimum_free_bytes,
                minimum_free_inodes: self.minimum_free_inodes,
                satisfied: reserve_ok,
            },
        })
        .expect("ready response serializes");
        (if completed && reserve_ok { 200 } else { 503 }, body)
    }

    /// Captures two fixed-size snapshots only. It deliberately performs no
    /// Store/index traversal and cannot trigger retirement or cleanup work.
    pub fn expiry_json(&self, store: &crate::store::Store) -> Vec<u8> {
        let scanner = self
            .expiration_scanner
            .get()
            .map(|status| status.snapshot_at(Instant::now()));
        let retirement = store
            .retirement_executor()
            .map(|executor| executor.snapshot());
        expiry_json_from_snapshots(scanner, retirement)
    }
}

fn expiry_json_from_snapshots(
    scanner: Option<crate::expiration::ExpirationScannerSnapshot>,
    retirement: Option<crate::retirement::RetirementSnapshot>,
) -> Vec<u8> {
    serde_json::to_vec(&ExpiryResponse {
        contract_version: "durable-streams-expiry-status-v1",
        capture: ExpiryCapture {
            consistency: "sequential_scanner_then_retirement",
            bounded: true,
        },
        scanner: scanner.map(expiry_scanner),
        retirement: retirement.map(expiry_retirement),
    })
    .expect("expiry status response serializes")
}

fn expiry_scanner(snapshot: crate::expiration::ExpirationScannerSnapshot) -> ExpiryScanner {
    use crate::expiration::{ExpirationReaperMode, ExpirationScannerEffectiveMode};

    ExpiryScanner {
        requested_mode: match snapshot.requested_mode {
            ExpirationReaperMode::Off => "off",
            ExpirationReaperMode::Observe => "observe",
            ExpirationReaperMode::Delete => "delete",
        },
        effective_mode: match snapshot.effective_mode {
            ExpirationScannerEffectiveMode::Off => "off",
            ExpirationScannerEffectiveMode::Observe => "observe",
            ExpirationScannerEffectiveMode::DeleteGated => "delete_gated",
            ExpirationScannerEffectiveMode::DeleteActive => "delete_active",
        },
        running: snapshot.running,
        initial_observe_pass_complete: snapshot.initial_observe_pass_complete,
        startup_grace_elapsed: snapshot.startup_grace_elapsed,
        deletion_eligible: snapshot.deletion_eligible,
        bulk_paused: snapshot.bulk_paused,
        clock_paused: snapshot.clock_paused,
        cursor: ExpiryCursor {
            pass_sequence: snapshot.pass_sequence,
            current_page_count: snapshot.current_page_count,
            wrapped: snapshot.cursor_wrapped,
        },
        index_entries: snapshot.index_entry_count,
        current: ExpiryCounts {
            checked: snapshot.current_checked,
            due: snapshot.current_due,
            due_fraction_display: due_fraction_display(
                snapshot.current_due,
                snapshot.current_checked,
            ),
        },
        completed: ExpiryCounts {
            checked: snapshot.completed_checked,
            due: snapshot.completed_due,
            due_fraction_display: due_fraction_display(
                snapshot.completed_due,
                snapshot.completed_checked,
            ),
        },
        totals: ExpiryTotals {
            checked: snapshot.total_checked,
            due: snapshot.total_due,
            pages: snapshot.total_pages,
            passes: snapshot.total_passes,
        },
        bulk_threshold: ExpiryBulkThreshold {
            numerator: snapshot.bulk_threshold_numerator,
            denominator: snapshot.bulk_threshold_denominator,
        },
        due_lag: ExpiryDueLag {
            latest_ms: snapshot.latest_due_lag.map(duration_millis),
            oldest_current_ms: snapshot.current_max_due_lag.map(duration_millis),
            oldest_completed_ms: snapshot.completed_max_due_lag.map(duration_millis),
        },
        clock_drift_ms: snapshot.latest_clock_drift.map(duration_millis),
        admission_attempts: snapshot.proactive_admission_attempts,
        outcomes: ExpiryOutcomes {
            observed: snapshot.outcomes.observed,
            renewed: snapshot.outcomes.renewed,
            fenced: snapshot.outcomes.fenced,
            soft_deleted: snapshot.outcomes.soft_deleted,
            reaped: snapshot.outcomes.reaped,
            stale: snapshot.outcomes.stale,
            failed: snapshot.outcomes.failed,
        },
        last_scan_unix_ms: snapshot.last_successful_scan_wall_time.map(unix_millis),
        last_completed_pass_unix_ms: snapshot.last_completed_pass_wall_time.map(unix_millis),
        last_completed_pass_duration_ms: snapshot.last_completed_pass_duration.map(duration_millis),
    }
}

fn expiry_retirement(snapshot: crate::retirement::RetirementSnapshot) -> ExpiryRetirement {
    ExpiryRetirement {
        capacities: RetirementCapacities {
            queue: snapshot.queue_capacity,
            coordinator: snapshot.coordinator_capacity,
            proactive_coordinator: snapshot.proactive_coordinator_capacity,
            interactive_coordinator_reserved: snapshot
                .coordinator_capacity
                .saturating_sub(snapshot.proactive_coordinator_capacity),
            physical_total: snapshot
                .interactive_physical_capacity
                .saturating_add(snapshot.proactive_physical_capacity),
            interactive_physical: snapshot.interactive_physical_capacity,
            proactive_physical: snapshot.proactive_physical_capacity,
        },
        jobs: RetirementJobs {
            total: snapshot.total_jobs,
            interactive_pending: snapshot.interactive_pending,
            proactive_pending: snapshot.proactive_pending,
            interactive_active: snapshot.active_interactive,
            proactive_active: snapshot.active_proactive,
        },
        physical: RetirementPhysical {
            interactive_queued: snapshot.physical_interactive_queued,
            proactive_queued: snapshot.physical_proactive_queued,
            interactive_active: snapshot.physical_interactive_active,
            proactive_active: snapshot.physical_proactive_active,
            workers_total: snapshot.cleanup_workers_total,
            workers_live: snapshot.cleanup_workers_live,
        },
        retries: RetirementRetries {
            heap_count: snapshot.retry_heap_count,
            cumulative_attempts: snapshot.cumulative_retry_attempts,
            cleanup_failed_current: snapshot.terminal_cleanup_failed_current,
        },
        outcomes: RetirementOutcomes {
            first_attempt: RetirementOutcomeCounts {
                successes: snapshot.first_attempt_successes,
                failures: snapshot.first_attempt_failures,
                cancellations: snapshot.first_attempt_cancellations,
            },
            terminal: RetirementOutcomeCounts {
                successes: snapshot.terminal_successes,
                failures: snapshot.terminal_failures,
                cancellations: snapshot.terminal_cancellations,
            },
        },
        timing: RetirementTiming {
            latest_cleanup_unix_ms: snapshot.latest_cleanup_wall_time.map(unix_millis),
            latest_cleanup_duration_ms: snapshot.latest_cleanup_duration.map(duration_millis),
            last_successful_cleanup_unix_ms: snapshot
                .last_successful_cleanup_wall_time
                .map(unix_millis),
            last_successful_cleanup_duration_ms: snapshot
                .last_successful_cleanup_duration
                .map(duration_millis),
        },
        reclaimed_local_bytes: snapshot.reclaimed_local_bytes,
        oldest_admission_age_ms: snapshot.oldest_admitted_age.map(duration_millis),
        closed: snapshot.closed,
    }
}

fn unix_millis(value: SystemTime) -> i64 {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => match i64::try_from(error.duration().as_millis()) {
            Ok(milliseconds) => -milliseconds,
            Err(_) => i64::MIN,
        },
    }
}

fn duration_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn due_fraction_display(due: u64, checked: u64) -> String {
    if checked == 0 {
        return "0.000000".to_string();
    }
    let scaled = u128::from(due)
        .saturating_mul(1_000_000)
        .checked_div(u128::from(checked))
        .unwrap_or(0);
    format!("{}.{:06}", scaled / 1_000_000, scaled % 1_000_000)
}

fn filesystem_free(path: &std::path::Path) -> std::io::Result<(u64, u64)> {
    #[cfg(test)]
    if let Some(value) = *TEST_FILESYSTEM_FREE.lock().unwrap() {
        return Ok(value);
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in data dir")
        })?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((
            (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64),
            stat.f_favail as u64,
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok((0, 0))
    }
}

#[cfg(test)]
static TEST_FILESYSTEM_FREE: std::sync::Mutex<Option<(u64, u64)>> = std::sync::Mutex::new(None);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expiration::{
        ExpirationOutcomeCounts, ExpirationReaperMode, ExpirationScannerEffectiveMode,
        ExpirationScannerSnapshot,
    };
    use crate::retirement::RetirementSnapshot;
    fn manifest() -> StoreManifestV1 {
        StoreManifestV1 {
            store_id: "2bc96d0b-9740-4f50-97c6-754b2b27d6b0".into(),
            store_generation: "ff8b5fa6-e786-4994-8da0-f14e9e79f318".into(),
            protocol_version: 1,
            layout_version: 1,
            durability_mode: "wal".into(),
            wal_shard_count: 1,
            stream_lane_count: 1,
            filesystem_uuid: "253f14d5-cbee-4df8-9e3c-e44c6e41501b".into(),
            creation_time: "2026-08-27T19:00:00Z".into(),
        }
    }
    #[test]
    fn reserve_failed_readiness_is_503_and_never_ready() {
        *TEST_FILESYSTEM_FREE.lock().unwrap() = Some((1, 1));
        let readiness = AdminReadiness::new(
            manifest(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            2,
            2,
        );
        readiness.ready();
        let (status, body) = readiness.json(std::path::Path::new("."));
        *TEST_FILESYSTEM_FREE.lock().unwrap() = None;
        assert_eq!(status, 503);
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "starting");
        assert_eq!(body["recovery"]["completed"], true);
        assert_eq!(body["reserve"]["satisfied"], false);
    }

    fn scanner_snapshot(
        requested_mode: ExpirationReaperMode,
        effective_mode: ExpirationScannerEffectiveMode,
    ) -> ExpirationScannerSnapshot {
        ExpirationScannerSnapshot {
            requested_mode,
            effective_mode,
            running: true,
            initial_observe_pass_complete: true,
            startup_grace_elapsed: true,
            deletion_eligible: true,
            bulk_paused: false,
            clock_paused: false,
            index_entry_count: 12,
            pass_sequence: 8,
            current_page_count: 3,
            last_scanned_stream_id: Some(4_242_424_242),
            cursor_wrapped: true,
            current_checked: 10,
            current_due: 3,
            completed_checked: 20,
            completed_due: 5,
            bulk_threshold_numerator: 1,
            bulk_threshold_denominator: 4,
            current_due_fraction: 0.3,
            completed_due_fraction: 0.25,
            total_checked: 30,
            total_due: 8,
            total_pages: 4,
            total_passes: 7,
            proactive_admission_attempts: 6,
            outcomes: ExpirationOutcomeCounts {
                observed: 30,
                renewed: 2,
                fenced: 1,
                soft_deleted: 1,
                reaped: 0,
                stale: 1,
                failed: 1,
            },
            last_completed_pass_wall_time: Some(UNIX_EPOCH - Duration::from_millis(2)),
            last_completed_pass_duration: Some(Duration::from_millis(7)),
            last_successful_scan_wall_time: Some(UNIX_EPOCH + Duration::from_millis(9)),
            latest_due_lag: Some(Duration::from_millis(10)),
            current_max_due_lag: Some(Duration::from_millis(11)),
            completed_max_due_lag: Some(Duration::from_millis(12)),
            latest_clock_drift: Some(Duration::from_millis(13)),
        }
    }

    fn assert_no_arrays(value: &serde_json::Value) {
        match value {
            serde_json::Value::Array(_) => panic!("expiry response must remain scalar-only"),
            serde_json::Value::Object(object) => {
                for value in object.values() {
                    assert_no_arrays(value);
                }
            }
            _ => {}
        }
    }

    fn assert_object_keys(value: &serde_json::Value, expected: &[&str]) {
        let object = value.as_object().expect("expected JSON object");
        let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
        actual.sort_unstable();
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn expiry_status_is_versioned_scalar_only_and_redacts_identity_fields() {
        let retirement = RetirementSnapshot {
            queue_capacity: 9,
            total_jobs: 4,
            interactive_pending: 1,
            proactive_pending: 2,
            active_interactive: 1,
            active_proactive: 0,
            coordinator_capacity: 8,
            proactive_coordinator_capacity: 3,
            interactive_physical_capacity: 5,
            proactive_physical_capacity: 6,
            physical_interactive_queued: 1,
            physical_proactive_queued: 2,
            physical_interactive_active: 3,
            physical_proactive_active: 4,
            cleanup_workers_total: 5,
            cleanup_workers_live: 4,
            retry_heap_count: 2,
            cumulative_retry_attempts: 7,
            terminal_cleanup_failed_current: 1,
            terminal_successes: 2,
            terminal_failures: 3,
            terminal_cancellations: 4,
            first_attempt_successes: 5,
            first_attempt_failures: 6,
            first_attempt_cancellations: 7,
            reclaimed_local_bytes: 8,
            latest_cleanup_wall_time: Some(UNIX_EPOCH - Duration::from_millis(3)),
            last_successful_cleanup_wall_time: Some(UNIX_EPOCH + Duration::from_millis(4)),
            latest_cleanup_duration: Some(Duration::from_millis(5)),
            last_successful_cleanup_duration: Some(Duration::from_millis(6)),
            oldest_admitted_age: Some(Duration::from_millis(7)),
            closed: false,
        };
        let body = expiry_json_from_snapshots(
            Some(scanner_snapshot(
                ExpirationReaperMode::Delete,
                ExpirationScannerEffectiveMode::DeleteActive,
            )),
            Some(retirement),
        );
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["contract_version"],
            "durable-streams-expiry-status-v1"
        );
        assert_eq!(
            value["capture"]["consistency"],
            "sequential_scanner_then_retirement"
        );
        assert_eq!(value["scanner"]["requested_mode"], "delete");
        assert_eq!(value["scanner"]["effective_mode"], "delete_active");
        assert_eq!(
            value["scanner"]["current"]["due_fraction_display"],
            "0.300000"
        );
        assert_eq!(value["scanner"]["last_completed_pass_unix_ms"], -2);
        assert_eq!(value["retirement"]["jobs"]["total"], 4);
        assert_eq!(value["retirement"]["physical"]["workers_live"], 4);
        assert_eq!(value["retirement"]["timing"]["latest_cleanup_unix_ms"], -3);
        assert_object_keys(
            &value,
            &["capture", "contract_version", "retirement", "scanner"],
        );
        assert_object_keys(
            &value["scanner"],
            &[
                "admission_attempts",
                "bulk_paused",
                "bulk_threshold",
                "clock_drift_ms",
                "clock_paused",
                "completed",
                "cursor",
                "deletion_eligible",
                "due_lag",
                "effective_mode",
                "index_entries",
                "initial_observe_pass_complete",
                "last_completed_pass_duration_ms",
                "last_completed_pass_unix_ms",
                "last_scan_unix_ms",
                "outcomes",
                "requested_mode",
                "running",
                "startup_grace_elapsed",
                "totals",
                "current",
            ],
        );
        assert_object_keys(
            &value["retirement"],
            &[
                "capacities",
                "closed",
                "jobs",
                "oldest_admission_age_ms",
                "outcomes",
                "physical",
                "reclaimed_local_bytes",
                "retries",
                "timing",
            ],
        );
        assert_no_arrays(&value);
        let text = String::from_utf8(body).unwrap();
        for forbidden in [
            "last_scanned_stream_id",
            "4242424242",
            "path",
            "stream_id",
            "store_id",
            "data_dir",
        ] {
            assert!(!text.contains(forbidden), "response leaked {forbidden}");
        }
    }

    #[test]
    fn expiry_status_projects_all_requested_effective_mode_pairs_and_null_components() {
        for (requested, effective, expected_requested, expected_effective) in [
            (
                ExpirationReaperMode::Off,
                ExpirationScannerEffectiveMode::Off,
                "off",
                "off",
            ),
            (
                ExpirationReaperMode::Observe,
                ExpirationScannerEffectiveMode::Observe,
                "observe",
                "observe",
            ),
            (
                ExpirationReaperMode::Delete,
                ExpirationScannerEffectiveMode::DeleteGated,
                "delete",
                "delete_gated",
            ),
            (
                ExpirationReaperMode::Delete,
                ExpirationScannerEffectiveMode::DeleteActive,
                "delete",
                "delete_active",
            ),
        ] {
            let body =
                expiry_json_from_snapshots(Some(scanner_snapshot(requested, effective)), None);
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["scanner"]["requested_mode"], expected_requested);
            assert_eq!(value["scanner"]["effective_mode"], expected_effective);
            assert!(value["retirement"].is_null());
        }
        let body = expiry_json_from_snapshots(None, None);
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["scanner"].is_null());
        assert!(value["retirement"].is_null());
    }

    #[test]
    fn expiry_time_helpers_are_pre_epoch_and_saturation_safe() {
        assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_millis(1)), -1);
        assert_eq!(unix_millis(UNIX_EPOCH + Duration::from_millis(1)), 1);
        assert_eq!(
            unix_millis(UNIX_EPOCH + Duration::from_millis(u64::MAX)),
            i64::MAX
        );
        assert_eq!(duration_millis(Duration::MAX), u64::MAX);
        assert_eq!(due_fraction_display(1, 3), "0.333333");
        assert_eq!(due_fraction_display(0, 0), "0.000000");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expiry_status_capture_reads_attached_scanner_and_executor_without_side_effects() {
        let directory =
            std::env::temp_dir().join(format!("ds-expiry-status-capture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let store = Arc::new(
            crate::store::Store::new_with_tier(
                directory.clone(),
                crate::tier::TierConfig::default(),
            )
            .unwrap(),
        );
        let scanner = crate::expiration::ExpirationScanner::start(
            &store,
            crate::expiration::ExpirationScannerConfig::default(),
        );
        store
            .init_retirement_executor_for_test(crate::retirement::RetirementConfig::default())
            .unwrap();
        let readiness = AdminReadiness::new(manifest(), "sha256:test".into(), 0, 0);
        readiness.attach_expiration_scanner(Arc::clone(scanner.status()));
        let body: serde_json::Value =
            serde_json::from_slice(&readiness.expiry_json(&store)).unwrap();
        assert_eq!(body["scanner"]["requested_mode"], "off");
        assert_eq!(body["scanner"]["effective_mode"], "off");
        assert!(body["retirement"].is_object());
        scanner.shutdown().await;
        store.retirement_executor().unwrap().shutdown().await;
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }
}
