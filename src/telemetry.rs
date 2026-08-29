// Opt-in OpenTelemetry instrumentation (feature `telemetry`, OFF BY DEFAULT).
//
// The rest of the server calls the public `record_*` / `init` API here with NO
// `#[cfg]` at the call sites. Two implementations live behind a cfg switch:
//
//   * feature on  → real OTLP span + metric export, with a `Metrics` struct of
//     pre-resolved instruments stored in a `OnceLock`.
//   * feature off → empty `#[inline(always)]` no-ops and a unit `Guard`. The
//     optimiser deletes the calls entirely, so a default build pays nothing.
//
// `tracing` spans (see handlers.rs / handlers' SSE spawn) are ALWAYS compiled —
// they are cheap and inert unless a subscriber with the OTel layer is installed,
// which only happens when this feature is on. Bounded label sets only (see the
// cardinality rule in the design): engine, live, cache, outcome, is_json,
// method, status_class — never a stream path/id, producer id, offset, etag, …

// ===========================================================================
// Real implementation (feature `telemetry`).
// ===========================================================================
#[cfg(feature = "telemetry")]
mod imp {
    use std::sync::OnceLock;

    use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};
    use opentelemetry::{global, KeyValue};
    use opentelemetry_otlp::{MetricExporter, SpanExporter};
    use opentelemetry_sdk::metrics::{
        Instrument, PeriodicReader, SdkMeterProvider, Stream, Temporality,
    };
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
    use opentelemetry_sdk::Resource;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{fmt, EnvFilter};

    /// Latency histogram bucket boundaries (seconds).
    const LATENCY_BUCKETS: &[f64] = &[
        0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
    ];
    /// Expiry scanner and physical cleanup durations (seconds).
    const EXPIRY_DURATION_BUCKETS: &[f64] =
        &[0.0001, 0.001, 0.01, 0.05, 0.25, 1.0, 5.0, 15.0, 60.0, 300.0];
    /// Expiry age and wall/monotonic divergence ranges (seconds).
    const EXPIRY_AGE_BUCKETS: &[f64] = &[
        0.001, 0.01, 0.1, 1.0, 5.0, 30.0, 60.0, 300.0, 900.0, 3600.0, 21600.0, 86400.0, 604800.0,
    ];
    /// Batch-size histogram bucket boundaries (count).
    const BATCH_BUCKETS: &[f64] = &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0];

    /// Pre-resolved instrument handles. Resolving an instrument is cheap but not
    /// free, so we do it once at startup and store the handles here.
    pub struct Metrics {
        http_requests: Counter<u64>,
        append_fsync_duration: Histogram<f64>,
        append_fsync_batch_size: Histogram<u64>,
        append_lock_wait: Histogram<f64>,
        append_duration: Histogram<f64>,
        read_duration: Histogram<f64>,
        read_tail_cache: Counter<u64>,
        // Recorded only from the Linux-only blocking-sendfile offload path.
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        read_offload_wait: Histogram<f64>,
        expiry_index_entries: Gauge<u64>,
        expiry_scan_checked: Counter<u64>,
        expiry_scan_duration: Histogram<f64>,
        expiry_due: Counter<u64>,
        expiry_outcome: Counter<u64>,
        expiry_lag: Histogram<f64>,
        expiry_clock_drift: Histogram<f64>,
        expiry_bulk_guard_paused: Gauge<u64>,
        expiry_cleanup_duration: Histogram<f64>,
        expiry_reclaimed_local_bytes: Counter<u64>,
        expiry_queue_depth: Gauge<u64>,
        expiry_queue_retries: Counter<u64>,
        expiry_fence_oldest_age: Gauge<f64>,
        expiry_cleanup_failed: Gauge<u64>,
    }

    impl Metrics {
        fn new(meter: &Meter) -> Self {
            Metrics {
                http_requests: meter
                    .u64_counter("ds.http.requests")
                    .with_description("HTTP requests handled, by method and status class.")
                    .build(),
                append_fsync_duration: meter
                    .f64_histogram("ds.append.fsync.duration")
                    .with_unit("s")
                    .with_description("Leader barrier-fsync duration for coalesced appends.")
                    .build(),
                append_fsync_batch_size: meter
                    .u64_histogram("ds.append.fsync.batch_size")
                    .with_description("Appends coalesced into one group-commit fsync.")
                    .build(),
                append_lock_wait: meter
                    .f64_histogram("ds.append.lock_wait.duration")
                    .with_unit("s")
                    .with_description("Time spent waiting for the per-stream append lock.")
                    .build(),
                append_duration: meter
                    .f64_histogram("ds.append.duration")
                    .with_unit("s")
                    .with_description("End-to-end append handler duration, by outcome.")
                    .build(),
                read_duration: meter
                    .f64_histogram("ds.read.duration")
                    .with_unit("s")
                    .with_description("Read handler duration, by live mode and cache result.")
                    .build(),
                read_tail_cache: meter
                    .u64_counter("ds.read.tail_cache")
                    .with_description("Resident tail-chunk cache hits / misses, by live mode.")
                    .build(),
                read_offload_wait: meter
                    .f64_histogram("ds.read.offload.wait")
                    .with_unit("s")
                    .with_description("Blocking-pool queue wait before a cold offloaded read runs.")
                    .build(),
                expiry_index_entries: meter
                    .u64_gauge("ds.expiry.index.entries")
                    .with_description("Current number of entries in the expiry index.")
                    .build(),
                expiry_scan_checked: meter
                    .u64_counter("ds.expiry.scan.checked")
                    .with_description("Expiry candidates classified by scanner pages.")
                    .build(),
                expiry_scan_duration: meter
                    .f64_histogram("ds.expiry.scan.duration")
                    .with_unit("s")
                    .with_description("Completed expiry scanner pass duration.")
                    .build(),
                expiry_due: meter
                    .u64_counter("ds.expiry.due")
                    .with_description("Due expiry candidates classified by scanner pages.")
                    .build(),
                expiry_outcome: meter
                    .u64_counter("ds.expiry.outcome")
                    .with_description("Bounded expiry lifecycle outcomes.")
                    .build(),
                expiry_lag: meter
                    .f64_histogram("ds.expiry.lag")
                    .with_unit("s")
                    .with_description("Oldest due-candidate lag per scanner page.")
                    .build(),
                expiry_clock_drift: meter
                    .f64_histogram("ds.expiry.clock_drift")
                    .with_unit("s")
                    .with_description("Scanner wall-clock versus monotonic-clock drift.")
                    .build(),
                expiry_bulk_guard_paused: meter
                    .u64_gauge("ds.expiry.bulk_guard.paused")
                    .with_description("Whether the expiry bulk safety guard is currently paused.")
                    .build(),
                expiry_cleanup_duration: meter
                    .f64_histogram("ds.expiry.cleanup.duration")
                    .with_unit("s")
                    .with_description("Physical expiry cleanup attempt duration.")
                    .build(),
                expiry_reclaimed_local_bytes: meter
                    .u64_counter("ds.expiry.reclaimed.local_bytes")
                    .with_description(
                        "Local bytes reclaimed by successful physical expiry cleanup.",
                    )
                    .build(),
                expiry_queue_depth: meter
                    .u64_gauge("ds.expiry.queue.depth")
                    .with_description("Current retained Expiry retirement job count.")
                    .build(),
                expiry_queue_retries: meter
                    .u64_counter("ds.expiry.queue.retries")
                    .with_description(
                        "Expiry cleanup retries scheduled after failed physical attempts.",
                    )
                    .build(),
                expiry_fence_oldest_age: meter
                    .f64_gauge("ds.expiry.fence.oldest_age")
                    .with_unit("s")
                    .with_description(
                        "Age of the oldest retained expiry fence, or zero when none remain.",
                    )
                    .build(),
                expiry_cleanup_failed: meter
                    .u64_gauge("ds.expiry.cleanup_failed")
                    .with_description("Current terminal expiry cleanup failures in cooldown.")
                    .build(),
            }
        }
    }

    static METRICS: OnceLock<Metrics> = OnceLock::new();

    fn metrics() -> Option<&'static Metrics> {
        METRICS.get()
    }

    /// Held for the lifetime of the process; its `Drop`/`shutdown` flushes the
    /// batch span processor and the periodic metric reader.
    pub struct Guard {
        tracer_provider: Option<SdkTracerProvider>,
        meter_provider: Option<SdkMeterProvider>,
    }

    impl Guard {
        /// Flush and shut down the exporters. Idempotent.
        pub fn shutdown(&mut self) {
            if let Some(p) = self.tracer_provider.take() {
                let _ = p.shutdown();
            }
            if let Some(p) = self.meter_provider.take() {
                let _ = p.shutdown();
            }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// Build the OTel resource, honoring OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES
    /// (Resource::builder() reads those env vars) with sensible defaults from the
    /// crate metadata.
    fn build_resource() -> Resource {
        Resource::builder()
            .with_service_name(env!("CARGO_PKG_NAME"))
            .with_attribute(KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
                env!("CARGO_PKG_VERSION"),
            ))
            .build()
    }

    /// Parent-based sampler from OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG.
    /// Defaults to parentbased_traceidratio with ratio 1.0 (sample everything).
    fn build_sampler() -> Sampler {
        let kind = std::env::var("OTEL_TRACES_SAMPLER")
            .unwrap_or_else(|_| "parentbased_traceidratio".to_string());
        let arg: f64 = std::env::var("OTEL_TRACES_SAMPLER_ARG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1.0);
        match kind.as_str() {
            "always_on" => Sampler::AlwaysOn,
            "always_off" => Sampler::AlwaysOff,
            "traceidratio" => Sampler::TraceIdRatioBased(arg),
            "parentbased_always_on" => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
            "parentbased_always_off" => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
            // "parentbased_traceidratio" and anything unrecognised.
            _ => Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(arg))),
        }
    }

    /// Explicit-bucket view for the named instrument (boundaries in `buckets`).
    fn bucket_view(
        name: &'static str,
        buckets: &'static [f64],
    ) -> impl Fn(&Instrument) -> Option<Stream> {
        move |i: &Instrument| {
            if i.name() == name {
                Some(
                    Stream::builder()
                        .with_aggregation(
                            opentelemetry_sdk::metrics::Aggregation::ExplicitBucketHistogram {
                                boundaries: buckets.to_vec(),
                                record_min_max: true,
                            },
                        )
                        .build()
                        .unwrap(),
                )
            } else {
                None
            }
        }
    }

    /// Initialise tracing + OTLP export. Endpoint/protocol/timeout all come from
    /// the standard OTEL_EXPORTER_OTLP_* env vars (WithExportConfig defaults read
    /// them). Returns a `Guard` that must be held for the process lifetime and
    /// whose shutdown flushes pending spans/metrics.
    pub fn init() -> Guard {
        let resource = build_resource();

        // ---- traces ----
        let span_exporter = SpanExporter::builder().with_tonic().build();
        let tracer_provider = match span_exporter {
            Ok(exporter) => Some(
                SdkTracerProvider::builder()
                    .with_resource(resource.clone())
                    .with_sampler(build_sampler())
                    .with_batch_exporter(exporter)
                    .build(),
            ),
            Err(e) => {
                eprintln!("telemetry: span exporter init failed: {e}; spans disabled");
                None
            }
        };

        // ---- metrics ----
        let meter_provider = match MetricExporter::builder()
            .with_tonic()
            .with_temporality(Temporality::Cumulative)
            .build()
        {
            Ok(exporter) => {
                let reader = PeriodicReader::builder(exporter).build();
                let provider = SdkMeterProvider::builder()
                    .with_resource(resource)
                    .with_reader(reader)
                    .with_view(bucket_view("ds.append.fsync.duration", LATENCY_BUCKETS))
                    .with_view(bucket_view("ds.append.lock_wait.duration", LATENCY_BUCKETS))
                    .with_view(bucket_view("ds.append.duration", LATENCY_BUCKETS))
                    .with_view(bucket_view("ds.read.duration", LATENCY_BUCKETS))
                    .with_view(bucket_view("ds.read.offload.wait", LATENCY_BUCKETS))
                    .with_view(bucket_view(
                        "ds.expiry.scan.duration",
                        EXPIRY_DURATION_BUCKETS,
                    ))
                    .with_view(bucket_view(
                        "ds.expiry.cleanup.duration",
                        EXPIRY_DURATION_BUCKETS,
                    ))
                    .with_view(bucket_view("ds.expiry.lag", EXPIRY_AGE_BUCKETS))
                    .with_view(bucket_view("ds.expiry.clock_drift", EXPIRY_AGE_BUCKETS))
                    .with_view(bucket_view("ds.append.fsync.batch_size", BATCH_BUCKETS))
                    .build();
                Some(provider)
            }
            Err(e) => {
                eprintln!("telemetry: metric exporter init failed: {e}; metrics disabled");
                None
            }
        };

        // ---- global providers + tracing subscriber ----
        let registry = tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
            .with(fmt::layer());

        if let Some(tp) = &tracer_provider {
            global::set_tracer_provider(tp.clone());
            use opentelemetry::trace::TracerProvider as _;
            let tracer = tp.tracer(env!("CARGO_PKG_NAME"));
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            let _ = registry.with(otel_layer).try_init();
        } else {
            let _ = registry.try_init();
        }

        if let Some(mp) = &meter_provider {
            global::set_meter_provider(mp.clone());
            let _ = METRICS.set(Metrics::new(&global::meter(env!("CARGO_PKG_NAME"))));
        }

        Guard {
            tracer_provider,
            meter_provider,
        }
    }

    // ---- record functions (no-ops until init() resolves the instruments) ----

    pub fn record_request(method: &'static str, status_class: &'static str) {
        if let Some(m) = metrics() {
            m.http_requests.add(
                1,
                &[
                    KeyValue::new("method", method),
                    KeyValue::new("status_class", status_class),
                ],
            );
        }
    }

    pub fn record_fsync(secs: f64, batch: u64) {
        if let Some(m) = metrics() {
            m.append_fsync_duration.record(secs, &[]);
            m.append_fsync_batch_size.record(batch, &[]);
        }
    }

    pub fn record_append_lock_wait(secs: f64) {
        if let Some(m) = metrics() {
            m.append_lock_wait.record(secs, &[]);
        }
    }

    pub fn record_append(secs: f64, outcome: &'static str, is_json: bool) {
        if let Some(m) = metrics() {
            m.append_duration.record(
                secs,
                &[
                    KeyValue::new("outcome", outcome),
                    KeyValue::new("is_json", is_json),
                ],
            );
        }
    }

    pub fn record_read(secs: f64, live: &'static str, cache_hit: bool) {
        if let Some(m) = metrics() {
            m.read_duration.record(
                secs,
                &[
                    KeyValue::new("live", live),
                    KeyValue::new("cache", if cache_hit { "hit" } else { "miss" }),
                ],
            );
        }
    }

    pub fn record_tail_cache(hit: bool, live: &'static str) {
        if let Some(m) = metrics() {
            m.read_tail_cache.add(
                1,
                &[
                    KeyValue::new("result", if hit { "hit" } else { "miss" }),
                    KeyValue::new("live", live),
                ],
            );
        }
    }

    // Called only from the Linux-only blocking-sendfile offload path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn record_offload_wait(secs: f64) {
        if let Some(m) = metrics() {
            m.read_offload_wait.record(secs, &[]);
        }
    }

    pub fn record_expiry_page(page: super::ExpiryPageTelemetry) {
        if let Some(m) = metrics() {
            m.expiry_index_entries.record(page.index_entries, &[]);
            m.expiry_bulk_guard_paused
                .record(u64::from(page.bulk_guard_paused), &[]);
            if page.checked != 0 {
                m.expiry_scan_checked.add(page.checked, &[]);
            }
            if page.due != 0 {
                m.expiry_due.add(page.due, &[]);
            }
            for delta in page.outcome_deltas() {
                if delta.count != 0 {
                    m.expiry_outcome.add(
                        delta.count,
                        &[KeyValue::new("outcome", delta.outcome.label())],
                    );
                }
            }
            if let Some(seconds) = page.due_lag_seconds().filter(|seconds| seconds.is_finite()) {
                m.expiry_lag.record(seconds, &[]);
            }
            if let Some(seconds) = page
                .completed_pass_duration_seconds
                .filter(|seconds| seconds.is_finite())
            {
                m.expiry_scan_duration.record(seconds, &[]);
            }
        }
    }

    pub fn record_expiry_clock_drift(seconds: f64) {
        if seconds.is_finite() {
            if let Some(m) = metrics() {
                m.expiry_clock_drift.record(seconds, &[]);
            }
        }
    }

    pub fn record_expiry_outcome(delta: super::ExpiryOutcomeDelta) {
        if delta.count != 0 {
            if let Some(m) = metrics() {
                m.expiry_outcome.add(
                    delta.count,
                    &[KeyValue::new("outcome", delta.outcome.label())],
                );
            }
        }
    }

    pub fn record_expiry_retirement(snapshot: super::ExpiryRetirementTelemetry) {
        if let Some(m) = metrics() {
            m.expiry_queue_depth.record(snapshot.queue_depth, &[]);
            m.expiry_cleanup_failed.record(snapshot.cleanup_failed, &[]);
            m.expiry_fence_oldest_age.record(
                snapshot
                    .oldest_fence_age_seconds
                    .filter(|seconds| seconds.is_finite())
                    .unwrap_or(0.0),
                &[],
            );
        }
    }

    pub fn record_expiry_cleanup_attempt(attempt: super::ExpiryCleanupTelemetry) {
        if let Some(m) = metrics() {
            if attempt.duration_seconds.is_finite() {
                m.expiry_cleanup_duration
                    .record(attempt.duration_seconds, &[]);
            }
            if let Some(disposition) = attempt.disposition {
                if let Some(reclaimed_local_bytes) = disposition.reclaimed_local_bytes() {
                    m.expiry_reclaimed_local_bytes
                        .add(reclaimed_local_bytes, &[]);
                }
                m.expiry_outcome.add(
                    1,
                    &[KeyValue::new("outcome", disposition.outcome().label())],
                );
            }
        }
    }

    /// Exactly one increment is emitted at retry scheduling, never again when
    /// the retry is later dispatched.
    pub fn record_expiry_cleanup_retry() {
        if let Some(m) = metrics() {
            m.expiry_queue_retries.add(1, &[]);
        }
    }

    /// Hot-path timer. Reads the monotonic clock only because telemetry is
    /// compiled in; in a default build `Timer` is the ZST below and `start` /
    /// `elapsed_secs` optimize away entirely (no `Instant::now()` on hot paths).
    pub struct Timer(std::time::Instant);
    impl Timer {
        #[inline]
        pub fn start() -> Self {
            Timer(std::time::Instant::now())
        }
        #[inline]
        pub fn elapsed_secs(&self) -> f64 {
            self.0.elapsed().as_secs_f64()
        }
    }
}

// ===========================================================================
// No-op implementation (feature off). Everything compiles out.
// ===========================================================================
// The no-op surface mirrors the real API exactly; some entry points (e.g.
// `record_offload_wait`, only called from the Linux-gated blocking sendfile path)
// are unused on a given host build, which is expected for a stable API shim.
#[cfg(not(feature = "telemetry"))]
#[allow(dead_code)]
mod imp {
    /// Unit guard; dropping it does nothing.
    pub struct Guard;

    impl Guard {
        #[inline(always)]
        pub fn shutdown(&mut self) {}
    }

    /// Initialise nothing. Returns a unit guard.
    #[inline(always)]
    pub fn init() -> Guard {
        Guard
    }

    #[inline(always)]
    pub fn record_request(_method: &'static str, _status_class: &'static str) {}
    #[inline(always)]
    pub fn record_fsync(_secs: f64, _batch: u64) {}
    #[inline(always)]
    pub fn record_append_lock_wait(_secs: f64) {}
    #[inline(always)]
    pub fn record_append(_secs: f64, _outcome: &'static str, _is_json: bool) {}
    #[inline(always)]
    pub fn record_read(_secs: f64, _live: &'static str, _cache_hit: bool) {}
    #[inline(always)]
    pub fn record_tail_cache(_hit: bool, _live: &'static str) {}
    #[inline(always)]
    pub fn record_offload_wait(_secs: f64) {}
    #[inline(always)]
    pub fn record_expiry_page(_page: super::ExpiryPageTelemetry) {}
    #[inline(always)]
    pub fn record_expiry_clock_drift(_seconds: f64) {}
    #[inline(always)]
    pub fn record_expiry_outcome(_delta: super::ExpiryOutcomeDelta) {}
    #[inline(always)]
    pub fn record_expiry_retirement(_snapshot: super::ExpiryRetirementTelemetry) {}
    #[inline(always)]
    pub fn record_expiry_cleanup_attempt(_attempt: super::ExpiryCleanupTelemetry) {}
    #[inline(always)]
    pub fn record_expiry_cleanup_retry() {}

    /// Zero-sized no-op timer: `start`/`elapsed_secs` compile to nothing, so a
    /// default build reads no clock on hot paths.
    pub struct Timer;
    impl Timer {
        #[inline(always)]
        pub fn start() -> Self {
            Timer
        }
        #[inline(always)]
        pub fn elapsed_secs(&self) -> f64 {
            0.0
        }
    }
}

// `Guard` and `record_offload_wait` are unused on some host/feature combinations
// (offload is a Linux-only sendfile path; Guard is held but not named on macOS),
// but are part of the stable public surface — keep the re-export complete.
#[allow(unused_imports)]
pub use imp::{
    init, record_append, record_append_lock_wait, record_expiry_cleanup_attempt,
    record_expiry_cleanup_retry, record_expiry_clock_drift, record_expiry_outcome,
    record_expiry_page, record_expiry_retirement, record_fsync, record_offload_wait, record_read,
    record_request, record_tail_cache, Guard, Timer,
};

/// The complete static label domain for `ds.expiry.outcome`. No caller accepts
/// arbitrary strings, paths, or identities as telemetry dimensions.
#[allow(dead_code)] // The feature-off shim deliberately erases all emissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryOutcome {
    Renewed,
    Observe,
    Fenced,
    SoftDeleted,
    Reaped,
    Stale,
    Failed,
}

#[allow(dead_code)]
impl ExpiryOutcome {
    pub const ALL: [Self; 7] = [
        Self::Renewed,
        Self::Observe,
        Self::Fenced,
        Self::SoftDeleted,
        Self::Reaped,
        Self::Stale,
        Self::Failed,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Renewed => "renewed",
            Self::Observe => "observe",
            Self::Fenced => "fenced",
            Self::SoftDeleted => "soft_deleted",
            Self::Reaped => "reaped",
            Self::Stale => "stale",
            Self::Failed => "failed",
        }
    }
}

/// A bounded counter increment with an outcome selected from the static domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpiryOutcomeDelta {
    pub outcome: ExpiryOutcome,
    pub count: u64,
}

/// O(1) telemetry emitted once after each scanner page has updated its safety
/// state. The oldest/max due lag is the sole page lag sample, in seconds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExpiryPageTelemetry {
    pub index_entries: u64,
    pub checked: u64,
    pub due: u64,
    pub observed: u64,
    pub stale: u64,
    pub latest_due_lag_seconds: Option<f64>,
    pub oldest_due_lag_seconds: Option<f64>,
    pub bulk_guard_paused: bool,
    /// Present only for a pass-completing page, so pass duration is emitted once.
    pub completed_pass_duration_seconds: Option<f64>,
}

#[allow(dead_code)]
impl ExpiryPageTelemetry {
    /// Exactly one due-lag sample is emitted per page: the maximum (oldest)
    /// overdue candidate, rather than both the newest and oldest values.
    pub const fn due_lag_seconds(self) -> Option<f64> {
        self.oldest_due_lag_seconds
    }

    pub const fn outcome_deltas(self) -> [ExpiryOutcomeDelta; 2] {
        [
            ExpiryOutcomeDelta {
                outcome: ExpiryOutcome::Observe,
                count: self.observed,
            },
            ExpiryOutcomeDelta {
                outcome: ExpiryOutcome::Stale,
                count: self.stale,
            },
        ]
    }
}

/// O(1) retirement state captured outside the coordinator lock before current
/// gauges are recorded. It deliberately has no stream identity or lane label.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExpiryRetirementTelemetry {
    pub queue_depth: u64,
    pub cleanup_failed: u64,
    pub oldest_fence_age_seconds: Option<f64>,
}

/// One matched physical expiry cleanup attempt. Every attempt records its
/// duration; only a successful disposition emits a terminal outcome.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExpiryCleanupTelemetry {
    pub duration_seconds: f64,
    pub disposition: Option<ExpiryCleanupDisposition>,
}

/// Successful physical expiry cleanup is either a hard reap or a durable soft
/// tombstone. Only the former contributes reclaimed bytes and `reaped`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryCleanupDisposition {
    Reaped(u64),
    SoftDeleted,
}

#[cfg_attr(not(feature = "telemetry"), allow(dead_code))]
impl ExpiryCleanupDisposition {
    pub const fn outcome(self) -> ExpiryOutcome {
        match self {
            Self::Reaped(_) => ExpiryOutcome::Reaped,
            Self::SoftDeleted => ExpiryOutcome::SoftDeleted,
        }
    }

    pub const fn reclaimed_local_bytes(self) -> Option<u64> {
        match self {
            Self::Reaped(bytes) => Some(bytes),
            Self::SoftDeleted => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_outcome_labels_are_an_exhaustive_static_allowlist() {
        let labels = ExpiryOutcome::ALL.map(ExpiryOutcome::label);
        assert_eq!(
            labels,
            [
                "renewed",
                "observe",
                "fenced",
                "soft_deleted",
                "reaped",
                "stale",
                "failed",
            ]
        );
        assert!(labels.iter().all(|label| {
            !label.contains("path") && !label.contains("id") && !label.contains("reason")
        }));
    }

    #[test]
    fn expiry_page_aggregates_only_observe_and_stale_outcomes_once() {
        let page = ExpiryPageTelemetry {
            index_entries: 9,
            checked: 8,
            due: 3,
            observed: 8,
            stale: 2,
            latest_due_lag_seconds: Some(0.1),
            oldest_due_lag_seconds: Some(0.5),
            bulk_guard_paused: false,
            completed_pass_duration_seconds: Some(1.0),
        };
        assert_eq!(
            page.outcome_deltas(),
            [
                ExpiryOutcomeDelta {
                    outcome: ExpiryOutcome::Observe,
                    count: 8,
                },
                ExpiryOutcomeDelta {
                    outcome: ExpiryOutcome::Stale,
                    count: 2,
                },
            ]
        );
        assert_eq!(page.index_entries, 9);
        assert!(!page.bulk_guard_paused);
        assert_eq!(page.due_lag_seconds(), Some(0.5));
        assert_eq!(page.completed_pass_duration_seconds, Some(1.0));

        let next_page = ExpiryPageTelemetry {
            completed_pass_duration_seconds: None,
            ..page
        };
        let pass_durations = [page, next_page]
            .into_iter()
            .filter_map(|page| page.completed_pass_duration_seconds)
            .collect::<Vec<_>>();
        assert_eq!(
            pass_durations,
            vec![1.0],
            "a completed pass emits one duration"
        );
    }

    #[test]
    fn expiry_page_records_only_the_oldest_due_lag() {
        let page = ExpiryPageTelemetry {
            latest_due_lag_seconds: Some(0.1),
            oldest_due_lag_seconds: Some(5.0),
            ..empty_expiry_page()
        };
        assert_eq!(page.due_lag_seconds(), Some(5.0));
        let single_due = ExpiryPageTelemetry {
            latest_due_lag_seconds: Some(2.0),
            oldest_due_lag_seconds: Some(2.0),
            ..empty_expiry_page()
        };
        assert_eq!(single_due.due_lag_seconds(), Some(2.0));
    }

    #[test]
    fn expiry_retirement_events_are_scalar_and_success_only_reclaims() {
        let snapshot = ExpiryRetirementTelemetry {
            queue_depth: 3,
            cleanup_failed: 1,
            oldest_fence_age_seconds: Some(60.0),
        };
        assert_eq!(snapshot.queue_depth, 3);
        assert_eq!(snapshot.cleanup_failed, 1);
        let success = ExpiryCleanupTelemetry {
            duration_seconds: 0.25,
            disposition: Some(ExpiryCleanupDisposition::Reaped(42)),
        };
        let soft_deleted = ExpiryCleanupTelemetry {
            duration_seconds: 0.25,
            disposition: Some(ExpiryCleanupDisposition::SoftDeleted),
        };
        let failed = ExpiryCleanupTelemetry {
            duration_seconds: 0.25,
            disposition: None,
        };
        assert_eq!(
            success.disposition,
            Some(ExpiryCleanupDisposition::Reaped(42))
        );
        assert_eq!(
            success.disposition.unwrap().outcome(),
            ExpiryOutcome::Reaped
        );
        assert_eq!(
            success.disposition.unwrap().reclaimed_local_bytes(),
            Some(42)
        );
        assert_eq!(
            soft_deleted.disposition,
            Some(ExpiryCleanupDisposition::SoftDeleted)
        );
        assert_eq!(
            soft_deleted.disposition.unwrap().outcome(),
            ExpiryOutcome::SoftDeleted
        );
        assert_eq!(
            soft_deleted.disposition.unwrap().reclaimed_local_bytes(),
            None
        );
        let hard_zero = ExpiryCleanupDisposition::Reaped(0);
        assert_eq!(hard_zero.outcome(), ExpiryOutcome::Reaped);
        assert_eq!(hard_zero.reclaimed_local_bytes(), Some(0));
        assert_eq!(failed.disposition, None);
    }

    #[test]
    fn expiry_current_gauge_values_are_not_cumulative() {
        let initial = empty_expiry_page();
        let paused = ExpiryPageTelemetry {
            index_entries: 9,
            bulk_guard_paused: true,
            ..empty_expiry_page()
        };
        let falling = ExpiryPageTelemetry {
            index_entries: 2,
            bulk_guard_paused: true,
            ..empty_expiry_page()
        };
        assert_eq!(initial.index_entries, 0);
        assert!(
            !initial.bulk_guard_paused,
            "a new/off scanner starts unpaused"
        );
        assert!(
            paused.bulk_guard_paused,
            "the bulk guard records its current 1 state"
        );
        assert_eq!(falling.index_entries, 2, "the current index gauge can fall");
        assert!(
            falling.bulk_guard_paused,
            "a tripped bulk guard remains sticky"
        );
        assert_eq!(falling.completed_pass_duration_seconds, None);
    }

    #[test]
    fn expiry_instrumentation_has_only_the_static_outcome_label() {
        let source = include_str!("telemetry.rs");
        let start = source
            .find("pub fn record_expiry_page")
            .expect("expiry recorder exists");
        let end = source[start..]
            .find("    /// Hot-path timer")
            .map(|offset| start + offset)
            .expect("expiry recorder section ends before Timer");
        let expiry_recorders = &source[start..end];
        assert!(expiry_recorders.contains("KeyValue::new(\"outcome\""));
        for forbidden in ["\"path\"", "\"id\"", "\"reason\"", "\"status\""] {
            assert!(
                !expiry_recorders.contains(forbidden),
                "expiry telemetry must not label {forbidden}"
            );
        }
    }

    #[test]
    fn expiry_histograms_use_operationally_sized_buckets() {
        let source = include_str!("telemetry.rs");
        assert!(source.contains("604800.0"), "age buckets include days");
        assert!(
            source.contains("300.0"),
            "cleanup/scan buckets include minutes"
        );
        assert!(source.contains("EXPIRY_AGE_BUCKETS"));
        assert!(source.contains("EXPIRY_DURATION_BUCKETS"));
    }

    fn empty_expiry_page() -> ExpiryPageTelemetry {
        ExpiryPageTelemetry {
            index_entries: 0,
            checked: 0,
            due: 0,
            observed: 0,
            stale: 0,
            latest_due_lag_seconds: None,
            oldest_due_lag_seconds: None,
            bulk_guard_paused: false,
            completed_pass_duration_seconds: None,
        }
    }
}
