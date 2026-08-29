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
    /// Batch-size histogram bucket boundaries (count).
    const BATCH_BUCKETS: &[f64] = &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0];
    /// Wall/monotonic clock divergence bucket boundaries (seconds).
    const CLOCK_DRIFT_BUCKETS: &[f64] = &[0.001, 0.01, 0.1, 1.0, 5.0, 30.0, 60.0, 300.0, 1800.0];

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
        expiry_completed_pass_due_fraction: Gauge<f64>,
        expiry_oldest_due_lag: Gauge<f64>,
        expiry_outcome: Counter<u64>,
        expiry_cleanup_duration: Histogram<f64>,
        expiry_reclaimed_local_bytes: Counter<u64>,
        expiry_queue_depth: Gauge<u64>,
        expiry_cleanup_active: Gauge<u64>,
        expiry_queue_retries: Counter<u64>,
        expiry_bulk_guard_paused: Gauge<u64>,
        expiry_clock_guard_paused: Gauge<u64>,
        expiry_clock_drift: Histogram<f64>,
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
                    .with_description("Current entries in the expiring-stream index.")
                    .build(),
                expiry_scan_checked: meter
                    .u64_counter("ds.expiry.scan.checked")
                    .with_description("Expiring-index entries checked by proactive scans.")
                    .build(),
                expiry_scan_duration: meter
                    .f64_histogram("ds.expiry.scan.duration")
                    .with_unit("s")
                    .with_description("Duration of a bounded proactive expiry scan page.")
                    .build(),
                expiry_due: meter
                    .u64_counter("ds.expiry.due")
                    .with_description("Expired streams found by proactive scans.")
                    .build(),
                expiry_completed_pass_due_fraction: meter
                    .f64_gauge("ds.expiry.pass.due_fraction")
                    .with_unit("1")
                    .with_description("Due fraction in the most recently completed scan pass.")
                    .build(),
                expiry_oldest_due_lag: meter
                    .f64_gauge("ds.expiry.lag")
                    .with_unit("s")
                    .with_description(
                        "Age past deadline of the oldest stream due in the current scan.",
                    )
                    .build(),
                expiry_outcome: meter
                    .u64_counter("ds.expiry.outcome")
                    .with_description("Expiration decisions, by bounded outcome.")
                    .build(),
                expiry_cleanup_duration: meter
                    .f64_histogram("ds.expiry.cleanup.duration")
                    .with_unit("s")
                    .with_description("End-to-end duration of one expiration cleanup attempt.")
                    .build(),
                expiry_reclaimed_local_bytes: meter
                    .u64_counter("ds.expiry.reclaimed.local_bytes")
                    .with_unit("By")
                    .with_description("Local stream bytes successfully reclaimed by expiration.")
                    .build(),
                expiry_queue_depth: meter
                    .u64_gauge("ds.expiry.queue.depth")
                    .with_description("Current queued expiration cleanup jobs.")
                    .build(),
                expiry_cleanup_active: meter
                    .u64_gauge("ds.expiry.cleanup.active")
                    .with_description("Current active expiration cleanup workers.")
                    .build(),
                expiry_queue_retries: meter
                    .u64_counter("ds.expiry.queue.retries")
                    .with_description("Expiration cleanup attempts requeued for retry.")
                    .build(),
                expiry_bulk_guard_paused: meter
                    .u64_gauge("ds.expiry.bulk_guard.paused")
                    .with_description("Sticky bulk-expiry safety pause (1 paused, 0 clear).")
                    .build(),
                expiry_clock_guard_paused: meter
                    .u64_gauge("ds.expiry.clock_guard.paused")
                    .with_description("Sticky clock-drift safety pause (1 paused, 0 clear).")
                    .build(),
                expiry_clock_drift: meter
                    .f64_histogram("ds.expiry.clock_drift")
                    .with_unit("s")
                    .with_description("Absolute wall/monotonic clock divergence.")
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
                    .with_view(bucket_view("ds.expiry.scan.duration", LATENCY_BUCKETS))
                    .with_view(bucket_view("ds.expiry.cleanup.duration", LATENCY_BUCKETS))
                    .with_view(bucket_view("ds.expiry.clock_drift", CLOCK_DRIFT_BUCKETS))
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

    pub fn record_expiry_index_entries(entries: u64) {
        if let Some(m) = metrics() {
            m.expiry_index_entries.record(entries, &[]);
        }
    }

    pub fn record_expiry_scan(checked: u64, due: u64, secs: f64) {
        if let Some(m) = metrics() {
            m.expiry_scan_checked.add(checked, &[]);
            m.expiry_due.add(due, &[]);
            m.expiry_scan_duration.record(secs, &[]);
        }
    }

    pub fn record_expiry_completed_pass(checked: u64, due: u64) {
        if let Some(m) = metrics() {
            m.expiry_completed_pass_due_fraction
                .record(expiry_due_fraction(checked, due), &[]);
        }
    }

    pub(super) fn expiry_due_fraction(checked: u64, due: u64) -> f64 {
        match checked {
            0 if due == 0 => 0.0,
            0 => 1.0,
            _ => (due as f64 / checked as f64).min(1.0),
        }
    }

    pub fn record_expiry_oldest_due_lag(secs: Option<f64>) {
        if let Some(m) = metrics() {
            let secs = secs
                .filter(|value| value.is_finite() && *value >= 0.0)
                .unwrap_or(0.0);
            m.expiry_oldest_due_lag.record(secs, &[]);
        }
    }

    pub fn record_expiry_outcome(outcome: &'static str) {
        if let Some(m) = metrics() {
            m.expiry_outcome.add(
                1,
                &[KeyValue::new("outcome", expiry_outcome_label(outcome))],
            );
        }
    }

    pub(super) fn expiry_outcome_label(outcome: &'static str) -> &'static str {
        match outcome {
            "renewed" | "observe" | "fenced" | "soft_deleted" | "reaped" | "stale" | "failed" => {
                outcome
            }
            // Keep accidental future call-site values from expanding metric
            // cardinality. New outcomes must be explicitly added here.
            _ => "failed",
        }
    }

    pub fn record_expiry_cleanup(secs: f64) {
        if let Some(m) = metrics() {
            m.expiry_cleanup_duration.record(secs, &[]);
        }
    }

    pub fn record_expiry_reclaimed_local_bytes(bytes: u64) {
        if let Some(m) = metrics() {
            m.expiry_reclaimed_local_bytes.add(bytes, &[]);
        }
    }

    pub fn record_expiry_queue(depth: u64, active: u64) {
        if let Some(m) = metrics() {
            m.expiry_queue_depth.record(depth, &[]);
            m.expiry_cleanup_active.record(active, &[]);
        }
    }

    pub fn record_expiry_retry() {
        if let Some(m) = metrics() {
            m.expiry_queue_retries.add(1, &[]);
        }
    }

    pub fn set_expiry_safety_pauses(bulk_paused: bool, clock_paused: bool) {
        if let Some(m) = metrics() {
            m.expiry_bulk_guard_paused
                .record(u64::from(bulk_paused), &[]);
            m.expiry_clock_guard_paused
                .record(u64::from(clock_paused), &[]);
        }
    }

    pub fn record_expiry_clock_drift(secs: f64) {
        if let Some(m) = metrics() {
            m.expiry_clock_drift.record(secs, &[]);
        }
    }

    // Called only from the Linux-only blocking-sendfile offload path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn record_offload_wait(secs: f64) {
        if let Some(m) = metrics() {
            m.read_offload_wait.record(secs, &[]);
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
    pub fn record_expiry_index_entries(_entries: u64) {}
    #[inline(always)]
    pub fn record_expiry_scan(_checked: u64, _due: u64, _secs: f64) {}
    #[inline(always)]
    pub fn record_expiry_completed_pass(_checked: u64, _due: u64) {}
    #[inline(always)]
    pub fn record_expiry_oldest_due_lag(_secs: Option<f64>) {}
    #[inline(always)]
    pub fn record_expiry_outcome(_outcome: &'static str) {}
    #[inline(always)]
    pub fn record_expiry_cleanup(_secs: f64) {}
    #[inline(always)]
    pub fn record_expiry_reclaimed_local_bytes(_bytes: u64) {}
    #[inline(always)]
    pub fn record_expiry_queue(_depth: u64, _active: u64) {}
    #[inline(always)]
    pub fn record_expiry_retry() {}
    #[inline(always)]
    pub fn set_expiry_safety_pauses(_bulk_paused: bool, _clock_paused: bool) {}
    #[inline(always)]
    pub fn record_expiry_clock_drift(_secs: f64) {}

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
    init, record_append, record_append_lock_wait, record_expiry_cleanup, record_expiry_clock_drift,
    record_expiry_completed_pass, record_expiry_index_entries, record_expiry_oldest_due_lag,
    record_expiry_outcome, record_expiry_queue, record_expiry_reclaimed_local_bytes,
    record_expiry_retry, record_expiry_scan, record_fsync, record_offload_wait, record_read,
    record_request, record_tail_cache, set_expiry_safety_pauses, Guard, Timer,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps the feature-on and feature-off reaper call surface identical. The
    /// feature-enabled build additionally proves every OTel instrument type and
    /// builder compiles against the pinned SDK version.
    #[test]
    fn expiry_reaper_metrics_surface_is_callable_without_identifiers() {
        record_expiry_index_entries(12);
        record_expiry_scan(10, 2, 0.001);
        record_expiry_completed_pass(10, 2);
        record_expiry_oldest_due_lag(Some(4.5));
        record_expiry_oldest_due_lag(None);
        for outcome in [
            "renewed",
            "observe",
            "fenced",
            "soft_deleted",
            "reaped",
            "stale",
            "failed",
        ] {
            record_expiry_outcome(outcome);
        }
        record_expiry_cleanup(0.002);
        record_expiry_queue(3, 1);
        record_expiry_retry();
        set_expiry_safety_pauses(true, false);
        record_expiry_clock_drift(0.25);
        record_expiry_reclaimed_local_bytes(4096);
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn expiry_outcome_label_set_is_closed() {
        assert_eq!(imp::expiry_outcome_label("reaped"), "reaped");
        assert_eq!(imp::expiry_outcome_label("/raw/path"), "failed");
        assert_eq!(imp::expiry_outcome_label("stream-id"), "failed");
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn expiry_completed_pass_due_fraction_is_bounded_and_defined_for_empty_passes() {
        assert_eq!(imp::expiry_due_fraction(0, 0), 0.0);
        assert_eq!(imp::expiry_due_fraction(0, 1), 1.0);
        assert_eq!(imp::expiry_due_fraction(4, 3), 0.75);
        assert_eq!(imp::expiry_due_fraction(2, 3), 1.0);
    }
}
