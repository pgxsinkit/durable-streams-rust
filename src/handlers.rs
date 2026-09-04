// HTTP protocol handlers for Durable Streams — engine-agnostic (see api.rs).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::{BufMut, Bytes, BytesMut};
use serde_json::value::RawValue;
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::api::{Body, Method, Req, Resp};
use crate::store::*;

// ---------- header names ----------
const H_NEXT_OFFSET: &str = "stream-next-offset";
const H_UP_TO_DATE: &str = "stream-up-to-date";
const H_CLOSED: &str = "stream-closed";
const H_CURSOR: &str = "stream-cursor";
const H_TTL: &str = "stream-ttl";
const H_EXPIRES_AT: &str = "stream-expires-at";
const H_SEQ: &str = "stream-seq";
const H_PRODUCER_ID: &str = "producer-id";
const H_PRODUCER_EPOCH: &str = "producer-epoch";
const H_PRODUCER_SEQ: &str = "producer-seq";
const H_PRODUCER_EXPECTED: &str = "producer-expected-seq";
const H_PRODUCER_RECEIVED: &str = "producer-received-seq";
const H_SSE_ENCODING: &str = "stream-sse-data-encoding";
const H_FORKED_FROM: &str = "stream-forked-from";
const H_FORK_OFFSET: &str = "stream-fork-offset";
const H_FORK_SUB_OFFSET: &str = "stream-fork-sub-offset";

static LONG_POLL_TIMEOUT_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(30_000);

pub fn set_long_poll_timeout(ms: u64) {
    LONG_POLL_TIMEOUT_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// Default server-defined maximum response chunk size (PROTOCOL.md §5.6): 4 MiB,
/// the same budget the upstream reference server uses (`MAX_READ_BATCH_BYTES` in
/// `packages/server-cloudflare/src/stream-object.ts`), so a reader paginating
/// against this server sees the same page sizes it would upstream. Without a cap
/// one GET returns the whole remainder of a stream, and a client that buffers
/// and parses the body scales its memory with the stream, not with the request.
pub const DEFAULT_MAX_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

static MAX_CHUNK_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(DEFAULT_MAX_CHUNK_BYTES);

/// Set the maximum bytes one read response may carry; `0` = unlimited.
pub fn set_max_chunk_bytes(bytes: u64) {
    MAX_CHUNK_BYTES.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

pub fn max_chunk_bytes() -> u64 {
    MAX_CHUNK_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Bytes read by the JSON boundary scan (test-only observability: a boundary
/// scan that re-reads the same bytes is the regression this counts).
#[cfg(test)]
pub(crate) static BOUNDARY_SCAN_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

// ---------- durability mode ----------

/// Server durability mode, chosen at startup via `--durability`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DurabilityMode {
    /// Durable: ack after the record is durable in the sharded WAL (group-commit fsync).
    #[default]
    Wal,
    /// No WAL, no fsync: ack on the page-cache write. Durability comes from replication
    /// (future).
    Memory,
}

static DURABILITY_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Parse the `--durability` value. `wal` | `memory`; `None` → usage error.
pub fn parse_durability(s: &str) -> Option<DurabilityMode> {
    match s {
        "wal" => Some(DurabilityMode::Wal),
        "memory" => Some(DurabilityMode::Memory),
        _ => None,
    }
}

pub fn set_durability(mode: DurabilityMode) {
    DURABILITY_MODE.store(mode as u8, std::sync::atomic::Ordering::Relaxed);
}

pub fn durability() -> DurabilityMode {
    match DURABILITY_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => DurabilityMode::Memory,
        _ => DurabilityMode::Wal,
    }
}

/// Test-only: serialization lock + RAII guard so parallel tests never race on
/// `DURABILITY_MODE`. Every test that drives the real append path acquires this
/// guard for its entire body; two such tests are then mutually exclusive.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{set_durability, set_max_chunk_bytes, DurabilityMode, DEFAULT_MAX_CHUNK_BYTES};
    use std::sync::{Arc, Mutex, MutexGuard};
    use tokio::sync::Notify;

    static MODE_LOCK: Mutex<()> = Mutex::new(());
    static APPEND_HOOK: Mutex<Option<Arc<AppendHook>>> = Mutex::new(None);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum AppendHookPoint {
        AfterAdmission,
        BeforeTailPublication,
        BeforeClosePublication,
        AfterPublication,
    }

    struct AppendHook {
        point: AppendHookPoint,
        reached: Notify,
        release: Notify,
    }

    pub(crate) struct AppendHookGuard {
        hook: Arc<AppendHook>,
    }

    impl AppendHookGuard {
        pub(crate) async fn reached(&self) {
            self.hook.reached.notified().await;
        }

        pub(crate) fn release(&self) {
            self.hook.release.notify_one();
        }
    }

    impl Drop for AppendHookGuard {
        fn drop(&mut self) {
            let mut installed = APPEND_HOOK
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if installed
                .as_ref()
                .is_some_and(|hook| Arc::ptr_eq(hook, &self.hook))
            {
                installed.take();
                self.hook.release.notify_waiters();
            }
        }
    }

    pub(crate) fn install_append_hook(point: AppendHookPoint) -> AppendHookGuard {
        let hook = Arc::new(AppendHook {
            point,
            reached: Notify::new(),
            release: Notify::new(),
        });
        let mut installed = APPEND_HOOK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(
            installed.is_none(),
            "an append test hook is already installed"
        );
        *installed = Some(Arc::clone(&hook));
        AppendHookGuard { hook }
    }

    pub(crate) async fn pause_append(point: AppendHookPoint) {
        let hook = APPEND_HOOK
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .filter(|hook| hook.point == point)
            .cloned();
        if let Some(hook) = hook {
            hook.reached.notify_one();
            hook.release.notified().await;
        }
    }

    /// Exclusive access to the process-wide server settings a test may change:
    /// the durability mode and the read chunk cap. Both are globals, so they
    /// share ONE lock — a cap set under a lock of its own could be observed by
    /// an unrelated test that holds only the durability guard. Dropping the
    /// guard restores both defaults.
    pub(crate) struct DurabilityGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl DurabilityGuard {
        pub(crate) fn wal() -> Self {
            let g = MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            set_durability(DurabilityMode::Wal);
            DurabilityGuard(g)
        }

        pub(crate) fn memory() -> Self {
            let g = MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            set_durability(DurabilityMode::Memory);
            DurabilityGuard(g)
        }

        /// Memory mode with the read chunk cap pinned for the guard's lifetime.
        pub(crate) fn memory_with_max_chunk(cap: u64) -> Self {
            let guard = Self::memory();
            set_max_chunk_bytes(cap);
            guard
        }
    }

    impl Drop for DurabilityGuard {
        fn drop(&mut self) {
            set_durability(DurabilityMode::Wal);
            set_max_chunk_bytes(DEFAULT_MAX_CHUNK_BYTES);
        }
    }
}

fn long_poll_timeout_dur() -> Duration {
    Duration::from_millis(LONG_POLL_TIMEOUT_MS.load(std::sync::atomic::Ordering::Relaxed))
}

const SSE_MAX_DURATION: Duration = Duration::from_secs(60);
/// Idle keep-alive cadence for SSE: when no new data arrives, emit a periodic
/// up-to-date control event so proxies/clients see liveness (still capped by
/// `SSE_MAX_DURATION`). Matches the reference servers' periodic control emits.
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);
const CACHEABLE: &str = "public, max-age=60, stale-while-revalidate=300";

// ---------- response building ----------

fn full(b: impl Into<Bytes>) -> Body {
    Body::Full(b.into())
}

fn empty() -> Body {
    Body::Empty
}

fn text_response(status: u16, msg: &str) -> Resp {
    let mut r = Resp::new(status);
    r.headers.push(("content-type", "text/plain".to_string()));
    r.body = full(msg.to_string());
    r
}

struct ResponseBuilder {
    resp: Resp,
}

impl ResponseBuilder {
    fn new(status: u16) -> Self {
        ResponseBuilder {
            resp: Resp::new(status),
        }
    }
    fn h(mut self, k: &'static str, v: String) -> Self {
        self.resp.headers.push((k, v));
        self
    }
    fn hs(mut self, k: &'static str, v: &'static str) -> Self {
        self.resp.headers.push((k, v.to_string()));
        self
    }
    fn body(mut self, b: Body) -> Resp {
        self.resp.body = b;
        self.resp
    }
}

// ---------- query parsing ----------

struct Query {
    offset: Option<String>,
    live: Option<String>,
    cursor: Option<u64>,
}

fn parse_query(q: Option<&str>) -> Result<Query, &'static str> {
    let mut out = Query {
        offset: None,
        live: None,
        cursor: None,
    };
    if let Some(q) = q {
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .to_string();
            match k {
                // A duplicate `offset` is rejected (matches the Go/TS reference
                // servers), not silently last-wins coalesced. `live`/`cursor`
                // keep last-wins (the Go server reads them with a last-value
                // getter and does not reject duplicates).
                "offset" => {
                    if out.offset.is_some() {
                        return Err("multiple offset parameters not allowed");
                    }
                    out.offset = Some(v);
                }
                "live" => out.live = Some(v),
                "cursor" => out.cursor = v.parse().ok(),
                _ => {}
            }
        }
    }
    Ok(out)
}

// Thin, intentional seams over the `Req` header accessors: every handler reads
// headers through these two free functions, so the underlying header source (and
// any future normalization — casing, trimming, multi-value policy) can change in
// one place without touching call sites. Kept as free functions for uniform,
// greppable call sites.
fn header_str<'a>(req: &'a Req, name: &str) -> Option<&'a str> {
    req.header(name)
}

fn header_is_true(req: &Req, name: &str) -> bool {
    req.header_is_true(name)
}

// ---------- main dispatch ----------

/// Map an HTTP method to a bounded, static label for metrics/spans.
fn method_label(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Put => "PUT",
        Method::Post => "POST",
        Method::Delete => "DELETE",
        Method::Head => "HEAD",
        Method::Options => "OPTIONS",
        Method::Other => "other",
    }
}

/// Bucket a status code into a bounded class label (`2xx`, `4xx`, …).
fn status_class(status: u16) -> &'static str {
    match status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        1 => "1xx",
        _ => "other",
    }
}

/// Coarse route bucket — deliberately NOT the stream id/path (unbounded
/// cardinality). Only the structural shape of the request is recorded.
fn route_label(path: &str) -> &'static str {
    if path == "/health" {
        "/health"
    } else {
        "/<stream>"
    }
}

#[allow(dead_code)]
pub async fn handle(store: Arc<Store>, req: Req) -> Resp {
    handle_with_admin(store, req, None).await
}

pub async fn handle_with_admin(
    store: Arc<Store>,
    req: Req,
    admin: Option<Arc<crate::admin_readiness::AdminReadiness>>,
) -> Resp {
    let method = method_label(req.method);
    let route = route_label(&req.path);
    // `ds.request` span. Skip everything heavy/unbounded: the store handle, the
    // full Req (bodies/Bytes), and the raw path — only bounded attributes are
    // recorded. The span is always compiled; it is exported only when the
    // `telemetry` feature is on and a subscriber is installed.
    let span = tracing::info_span!(
        "ds.request",
        http.method = method,
        route = route,
        status_class = tracing::field::Empty
    );
    let resp = dispatch(store, req, admin).instrument(span.clone()).await;
    span.record("status_class", status_class(resp.status));
    crate::telemetry::record_request(method, status_class(resp.status));
    // Constant security headers (nosniff, CORP) are emitted by the engine's
    // response writer — see api::SECURITY_HEADERS — to avoid two String
    // allocations on every response.
    resp
}

async fn dispatch(
    store: Arc<Store>,
    req: Req,
    admin: Option<Arc<crate::admin_readiness::AdminReadiness>>,
) -> Resp {
    let path = req.path.clone();
    if let Ok(normalized) = percent_encoding::percent_decode_str(&path).decode_utf8() {
        if normalized.starts_with("/_admin/") && normalized.as_ref() != path {
            return text_response(400, "encoded admin route aliases are forbidden");
        }
    }
    if req.method == Method::Options {
        cors_preflight()
    } else if path == "/health" {
        text_response(200, "ok")
    } else if path.starts_with("/_admin/") {
        match (path.as_str(), req.method, admin) {
            ("/_admin/ready", Method::Get, Some(admin)) => {
                let (status, body) = admin.json(&store.data_dir);
                let mut response = Resp::new(status);
                response
                    .headers
                    .push(("content-type", "application/json".to_string()));
                // The document reports live state (recovery, reserve) and a
                // startup-configured bound that a restart may change under an
                // unchanged store identity. A consumer revalidates by re-reading
                // it, so a stored copy would defeat the only defence it has.
                response
                    .headers
                    .push(("cache-control", "no-store".to_string()));
                response.body = full(body);
                response
            }
            ("/_admin/inventory", Method::Get, Some(_)) => {
                inventory_response(&store, req.query.as_deref())
            }
            ("/_admin/expiry", Method::Get, Some(_)) => expiry_status_response(),
            (_, Method::Get, _) => text_response(404, "admin endpoint not found"),
            _ => text_response(405, "admin endpoints are read-only"),
        }
    } else if crate::subscriptions::is_control_path(&path) {
        store.subscriptions.clone().handle(store, req).await
    } else {
        match req.method {
            Method::Put => handle_create(store, req, path).await,
            Method::Post => handle_append(store, req, path).await,
            Method::Get => handle_read(store, req, path).await,
            Method::Head => handle_head(store, path).await,
            Method::Delete => handle_delete(store, path).await,
            Method::Options => unreachable!("OPTIONS handled before route dispatch"),
            Method::Other => text_response(405, "method not allowed"),
        }
    }
}

/// Advertise the request headers understood by the protocol without granting
/// cross-origin access. An operator that intentionally exposes browser access
/// can add an origin policy at the authenticated edge; the storage process must
/// not make every stream and control route readable with `allow-origin: *`.
fn cors_preflight() -> Resp {
    ResponseBuilder::new(204)
        .hs(
            "access-control-allow-methods",
            "GET, POST, PUT, DELETE, HEAD, OPTIONS",
        )
        .hs(
            "access-control-allow-headers",
            "content-type, authorization, If-None-Match, Stream-Seq, Stream-TTL, Stream-Expires-At, Stream-Closed, Producer-Id, Producer-Epoch, Producer-Seq, Stream-Forked-From, Stream-Fork-Offset, Stream-Fork-Sub-Offset",
        )
        .body(empty())
}

#[cfg(test)]
mod cors_policy_tests {
    use super::*;

    #[test]
    fn preflight_advertises_headers_without_granting_cross_origin_reads() {
        let response = cors_preflight();
        assert_eq!(response.status, 204);
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| *name == "access-control-allow-headers"
                && value.to_ascii_lowercase().contains("if-none-match")));
        assert!(!response
            .headers
            .iter()
            .any(|(name, _)| *name == "access-control-allow-origin"));
        assert!(!crate::api::SECURITY_HEADERS
            .iter()
            .any(|(name, _)| *name == "access-control-allow-origin"));
    }
}

fn inventory_response(store: &Store, query: Option<&str>) -> Resp {
    const DEFAULT_LIMIT: usize = 100;
    const MAX_LIMIT: usize = 1000;
    let mut cursor: Option<(u64, String)> = None;
    let mut limit = DEFAULT_LIMIT;
    if let Some(query) = query {
        for part in query.split('&') {
            let Some((key, value)) = part.split_once('=') else {
                return text_response(400, "invalid inventory query");
            };
            match key {
                "cursor" => match decode_inventory_cursor(value) {
                    Some(value) => cursor = Some(value),
                    None => return text_response(400, "invalid inventory cursor"),
                },
                "limit" => match value.parse::<usize>() {
                    Ok(n) if (1..=MAX_LIMIT).contains(&n) => limit = n,
                    _ => return text_response(400, "inventory limit must be 1..=1000"),
                },
                _ => return text_response(400, "unknown inventory query parameter"),
            }
        }
    }
    let (generation, entries, more) = match store.inventory_page(
        cursor.as_ref().map(|(generation, _)| *generation),
        cursor.as_ref().map(|(_, path)| path.as_str()),
        limit,
    ) {
        Ok(page) => page,
        Err(crate::store::InventoryPageError::GenerationChanged) => {
            return text_response(409, "inventory changed; restart pagination")
        }
    };
    let next_cursor = if more {
        entries
            .last()
            .map(|entry| encode_inventory_cursor(generation, &entry.path))
    } else {
        None
    };
    #[derive(serde::Serialize)]
    struct Item<'a> {
        path: &'a str,
        closed: bool,
        deleted: bool,
        durable_bytes: u64,
    }
    #[derive(serde::Serialize)]
    struct Page<'a> {
        streams: Vec<Item<'a>>,
        next_cursor: Option<String>,
    }
    let body = serde_json::to_vec(&Page {
        streams: entries
            .iter()
            .map(|entry| Item {
                path: &entry.path,
                closed: entry.closed,
                deleted: entry.deleted,
                durable_bytes: entry.durable_bytes,
            })
            .collect(),
        next_cursor,
    })
    .expect("inventory serializes");
    let mut response = Resp::new(200);
    response
        .headers
        .push(("content-type", "application/json".to_string()));
    response.body = full(body);
    response
}

fn expiry_status_response() -> Resp {
    let Some(status) = crate::expiry_reaper::status() else {
        return text_response(404, "expiry coordinator not running");
    };
    match serde_json::to_vec(&status) {
        Ok(body) => ResponseBuilder::new(200)
            .hs("content-type", "application/json")
            .body(full(body)),
        Err(error) => {
            tracing::error!(%error, "expiry status serialization failed");
            text_response(500, "expiry status unavailable")
        }
    }
}

fn encode_inventory_cursor(generation: u64, path: &str) -> String {
    format!(
        "{generation}.{}",
        percent_encoding::utf8_percent_encode(path, percent_encoding::NON_ALPHANUMERIC)
    )
}

fn decode_inventory_cursor(cursor: &str) -> Option<(u64, String)> {
    let (generation, encoded_path) = cursor.split_once('.')?;
    if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let generation = generation.parse().ok()?;
    let decoded = percent_encoding::percent_decode_str(encoded_path)
        .decode_utf8()
        .ok()?
        .into_owned();
    // Cursor bytes are part of the pagination protocol, so accept exactly one
    // spelling. This prevents aliases such as raw `&` and lowercase escapes.
    (encode_inventory_cursor(generation, &decoded) == cursor).then_some((generation, decoded))
}

// ---------- PUT (create) ----------

fn parse_ttl(v: &str) -> Result<u64, ()> {
    if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    if v.len() > 1 && v.starts_with('0') {
        return Err(());
    }
    v.parse().map_err(|_| ())
}

/// Minimal RFC 3339 parser (YYYY-MM-DDTHH:MM:SS[.frac](Z|±hh:mm)).
fn parse_rfc3339(s: &str) -> Result<SystemTime, ()> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return Err(());
    }
    let num = |r: std::ops::Range<usize>| -> Result<i64, ()> {
        let part = s.get(r).ok_or(())?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return Err(());
        }
        part.parse().map_err(|_| ())
    };
    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(());
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // Reject seconds == 60 (leap seconds), matching the reference server's
    // `new Date(...)` which returns Invalid Date for sec >= 60.
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 59 {
        return Err(());
    }
    // Per-month day limits, with leap-year February. This rejects impossible
    // calendar dates (e.g. 2021-02-31) instead of silently rolling them over
    // into a different expiry instant.
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let max_day = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(()),
    };
    if !(1..=max_day).contains(&d) {
        return Err(());
    }
    let mut idx = 19;
    if b.get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == start {
            return Err(());
        }
    }
    let tz_offset_secs: i64 = match b.get(idx) {
        Some(b'Z') | Some(b'z') if idx + 1 == b.len() => 0,
        Some(b'+') | Some(b'-') if idx + 6 == b.len() && b[idx + 3] == b':' => {
            let sign = if b[idx] == b'+' { 1 } else { -1 };
            let oh = num(idx + 1..idx + 3)?;
            let om = num(idx + 4..idx + 6)?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return Err(()),
    };
    // Days-from-civil (Howard Hinnant's algorithm).
    let (y2, mo2) = if mo <= 2 { (y - 1, mo + 12) } else { (y, mo) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (mo2 - 3) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + h * 3600 + mi * 60 + sec - tz_offset_secs;
    if secs < 0 {
        return Err(());
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64))
}

#[cfg(test)]
async fn retire_without_process_coordinator(
    store: &Arc<Store>,
    candidate: &ExpiryCandidate,
    durability: RetirementDurability,
) -> std::io::Result<crate::expiry_reaper::CoordinatedOutcome> {
    use crate::expiry_reaper::CoordinatedOutcome;
    let prepared = match durability {
        RetirementDurability::Expiry => {
            store
                .prepare_expiry_retirement(candidate, SystemTime::now())
                .await
        }
        RetirementDurability::Explicit => store.prepare_delete(&candidate.stream()).await,
    };
    match prepared {
        PrepareRetirement::Renewed => return Ok(CoordinatedOutcome::Renewed),
        PrepareRetirement::Stale => return Ok(CoordinatedOutcome::Stale),
        PrepareRetirement::Gone => return Ok(CoordinatedOutcome::Gone),
        PrepareRetirement::Ready => {}
    }
    let stream = candidate.stream();
    #[cfg(target_os = "linux")]
    crate::sse_reactor::wake_stream(&stream);
    store
        .subscriptions
        .clone()
        .on_stream_deleted(store.clone(), &stream.path, candidate.stream_id())
        .await?;
    // `finish_retirement` deliberately returns only one physical step so the
    // production coordinator can pace a newly eligible fork parent without
    // taking another bounded admission. Direct unit tests do not start that
    // process coordinator, so preserve the same continuation semantics here.
    // The parent's subscription transition already ran when it was originally
    // soft-deleted; only the root candidate needs the transition above.
    let mut current = candidate.clone();
    loop {
        let step = store.finish_retirement(&current, durability).await?;
        match step.cascade {
            Some(parent) => current = parent,
            None => return Ok(CoordinatedOutcome::Retired(step.outcome)),
        }
    }
}

pub(crate) async fn enqueue_expired_before_not_found(
    _store: &Arc<Store>,
    candidate: &ExpiryCandidate,
    now: SystemTime,
) {
    // StreamLookup::Expired also covers a non-expired stream already fenced by
    // explicit DELETE. Never downgrade that retirement to Expiry durability.
    if !candidate.stream().is_expired_at(now) {
        return;
    }
    #[cfg(test)]
    if crate::expiry_reaper::status().is_none() {
        if let Err(error) =
            retire_without_process_coordinator(_store, candidate, RetirementDurability::Expiry)
                .await
        {
            tracing::error!(%error, stream_id = candidate.stream_id(), "test lazy expiry retirement failed");
        }
        return;
    }
    match crate::expiry_reaper::enqueue_expired(candidate.clone()) {
        Ok(()) | Err(crate::expiry_reaper::EnqueueError::AlreadyQueued) => {}
        Err(error) => {
            tracing::warn!(
                ?error,
                stream_id = candidate.stream_id(),
                "lazy expiry queue unavailable; a scan or later request will retry"
            );
        }
    }
}

async fn coordinated_retire_and_wait(
    _store: &Arc<Store>,
    candidate: &ExpiryCandidate,
    durability: RetirementDurability,
) -> std::io::Result<crate::expiry_reaper::CoordinatedOutcome> {
    #[cfg(test)]
    if crate::expiry_reaper::status().is_none() {
        return retire_without_process_coordinator(_store, candidate, durability).await;
    }
    crate::expiry_reaper::retire_and_wait(candidate.clone(), durability).await
}

/// Expired PUT may race a lazy GET/scanner that already admitted this exact
/// incarnation. Join that bounded retirement instead of converting the
/// coordinator's `AlreadyQueued` marker into a transient 503.
async fn coordinated_retire_or_join_and_wait(
    _store: &Arc<Store>,
    candidate: &ExpiryCandidate,
    durability: RetirementDurability,
) -> std::io::Result<crate::expiry_reaper::CoordinatedOutcome> {
    #[cfg(test)]
    if crate::expiry_reaper::status().is_none() {
        return retire_without_process_coordinator(_store, candidate, durability).await;
    }
    crate::expiry_reaper::retire_or_join_and_wait(candidate.clone(), durability).await
}

fn retirement_busy() -> Resp {
    ResponseBuilder::new(503)
        .hs("retry-after", "1")
        .body(full("stream retirement in progress"))
}

async fn handle_create(store: Arc<Store>, req: Req, path: String) -> Resp {
    // Read Content-Type ONCE: `content_type_hdr` carries presence (used for fork
    // inheritance / match below); `content_type` is the resolved value with the
    // octet-stream default.
    let content_type_hdr = header_str(&req, "content-type").map(|s| s.to_string());
    let content_type = content_type_hdr
        .as_deref()
        .unwrap_or("application/octet-stream")
        .to_string();
    let ttl_raw = header_str(&req, H_TTL).map(|s| s.to_string());
    let exp_raw = header_str(&req, H_EXPIRES_AT).map(|s| s.to_string());
    if ttl_raw.is_some() && exp_raw.is_some() {
        return text_response(400, "Stream-TTL conflicts with Stream-Expires-At");
    }
    let ttl_seconds = match &ttl_raw {
        Some(v) => match parse_ttl(v) {
            Ok(t) => Some(t),
            Err(_) => return text_response(400, "invalid Stream-TTL"),
        },
        None => None,
    };
    let expires_at = match &exp_raw {
        Some(v) => match parse_rfc3339(v) {
            Ok(t) => Some(t),
            Err(_) => return text_response(400, "invalid Stream-Expires-At"),
        },
        None => None,
    };
    let create_closed = header_is_true(&req, H_CLOSED);
    let host = header_str(&req, "host").map(|s| s.to_string());

    // ---- fork header parsing & validation ----
    let forked_from = header_str(&req, H_FORKED_FROM).map(|s| s.to_string());
    let fork_offset_raw = header_str(&req, H_FORK_OFFSET).map(|s| s.to_string());
    let sub_offset_raw = header_str(&req, H_FORK_SUB_OFFSET).map(|s| s.to_string());
    if forked_from.is_none() && (fork_offset_raw.is_some() || sub_offset_raw.is_some()) {
        return text_response(400, "fork headers require Stream-Forked-From");
    }
    let sub_offset: Option<u64> = match &sub_offset_raw {
        None => None,
        Some(v) => {
            if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit()) {
                return text_response(400, "malformed Stream-Fork-Sub-Offset");
            }
            match v.parse() {
                Ok(n) => Some(n),
                Err(_) => return text_response(400, "malformed Stream-Fork-Sub-Offset"),
            }
        }
    };
    if sub_offset.unwrap_or(0) > 0 && fork_offset_raw.is_none() {
        return text_response(400, "Stream-Fork-Sub-Offset requires Stream-Fork-Offset");
    }

    // Resolve the fork source and the fork point (logical byte offset).
    let mut parent: Option<Arc<StreamState>> = None;
    let mut base_offset: u64 = 0;
    let mut content_type = content_type;
    let mut ttl_seconds = ttl_seconds;
    let mut expires_at = expires_at;
    let mut exp_raw = exp_raw;
    if let Some(src_path) = &forked_from {
        let lookup_now = SystemTime::now();
        let src = match store.lookup_at(src_path, lookup_now, false) {
            StreamLookup::Live(stream) => stream,
            StreamLookup::Gone(_) => return text_response(409, "fork source is deleted"),
            StreamLookup::Missing => return text_response(404, "fork source not found"),
            StreamLookup::Expired(candidate) => {
                enqueue_expired_before_not_found(&store, &candidate, lookup_now).await;
                return text_response(404, "fork source not found");
            }
        };
        match &content_type_hdr {
            None => content_type = src.config.content_type.clone(),
            Some(ct) => {
                if media_type(ct) != media_type(&src.config.content_type) {
                    return text_response(409, "fork content-type mismatch");
                }
            }
        }
        let src_tail = src.tail().bytes;
        if sub_offset_raw.is_some() && src_tail == 0 {
            return text_response(400, "sub-offset on empty source stream");
        }
        // Fork-Offset omitted → divergence at the source's current tail.
        let anchor = match parse_offset(fork_offset_raw.as_deref()) {
            Ok(ParsedOffset::Start) if fork_offset_raw.is_none() => src_tail,
            Ok(ParsedOffset::Start) => 0,
            Ok(ParsedOffset::Now) => src_tail,
            Ok(ParsedOffset::At(b)) => {
                if b > src_tail {
                    return text_response(400, "fork offset beyond stream length");
                }
                b
            }
            Err(_) => return text_response(400, "malformed fork offset"),
        };
        let fork_point = match sub_offset.unwrap_or(0) {
            0 => anchor,
            sub if src.is_json => {
                // Sub-offset counts MESSAGES past the anchor. In the JSON wire
                // form (`value,value,…,`) a message boundary is a TOP-LEVEL
                // comma, so the count goes through the same value-boundary
                // scanner the tier's sealing path and the read chunk cap use.
                // Counting raw commas instead also counts commas inside strings
                // and nested objects/arrays, which places the fork point INSIDE a
                // value: every later read of that fork then starts mid-value, so
                // it serves malformed JSON and the chunk cap's boundary scanner
                // (which assumes a range of whole top-level values) can find no
                // boundary at all.
                //
                // NOTE: this materializes the whole `[anchor, src_tail)` range to
                // scan for the Nth boundary, even for a small `sub` over a huge
                // stream — O(tail) memory. Acceptable here: fork-create is a cold
                // control op, not a hot path. A bounded-window scan would remove
                // the cost.
                let data = match read_range_bytes(&src, anchor, src_tail).await {
                    Ok(d) => d,
                    // A short/cold read must not be miscounted as a value boundary.
                    Err(_) => return text_response(503, "fork source read failed"),
                };
                match crate::tier::nth_json_value_boundary(&data, sub) {
                    0 => return text_response(400, "sub-offset overshoots message count"),
                    adv => anchor + adv,
                }
            }
            sub => {
                if anchor + sub > src_tail {
                    return text_response(400, "sub-offset overshoots message length");
                }
                anchor + sub
            }
        };
        // TTL/expiry inheritance: only when the fork specifies neither.
        if ttl_seconds.is_none() && exp_raw.is_none() {
            ttl_seconds = src.config.ttl_seconds;
            expires_at = src.config.expires_at;
            exp_raw = src.config.expires_at_raw.clone();
        }
        base_offset = fork_point;
        parent = Some(src);
    }

    let body = req.body.clone();

    let config = StreamConfig {
        content_type: content_type.clone(),
        ttl_seconds,
        expires_at,
        expires_at_raw: exp_raw,
        create_closed,
        forked_from,
        fork_offset_raw,
        fork_sub_offset: sub_offset,
    };

    let is_json = is_json_content_type(&content_type);
    // Validate / transform initial body before creating.
    let wire: Option<Bytes> = if body.is_empty() {
        None
    } else {
        match encode_wire(&body, is_json, true) {
            Ok(w) => Some(w),
            Err(msg) => return text_response(400, msg),
        }
    };

    // Run create on the blocking pool: it opens the data file and does a durable
    // (fsync) `.meta` write, which would otherwise block an async worker for the
    // whole fsync. Under concurrent stream creation that throttles creates to
    // ~(worker_count / fsync_latency) and times them out (the "stream creation
    // doesn't scale past ~200 PUTs" finding). On the blocking pool many creates
    // fsync concurrently and the async workers stay free to dispatch.
    let result = {
        let store = store.clone();
        let create_path = path.clone();
        let create_config = config.clone();
        let create_parent = parent.clone();
        match tokio::task::spawn_blocking(move || {
            store.create(&create_path, create_config, create_parent, base_offset)
        })
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return retirement_busy()
            }
            Ok(Err(e)) => return text_response(500, &e.to_string()),
            Err(_) => return text_response(500, "create task failed"),
        }
    };
    let result = match result {
        CreateResult::Expired(candidate) => {
            // CreateResult::Expired also represents a non-expired incarnation
            // already fenced by an explicit DELETE. Only a genuinely expired
            // stream may enter the Expiry-durability path; otherwise preserve
            // the outstanding explicit retirement and ask the client to retry.
            if !candidate.stream().is_expired_at(SystemTime::now()) {
                return retirement_busy();
            }
            match coordinated_retire_or_join_and_wait(
                &store,
                &candidate,
                RetirementDurability::Expiry,
            )
            .await
            {
                Ok(crate::expiry_reaper::CoordinatedOutcome::Retired(_)) => {}
                Ok(crate::expiry_reaper::CoordinatedOutcome::Gone) => {
                    return text_response(409, "stream exists with different configuration")
                }
                Ok(
                    crate::expiry_reaper::CoordinatedOutcome::Renewed
                    | crate::expiry_reaper::CoordinatedOutcome::Stale,
                ) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return retirement_busy()
                }
                Err(error) => {
                    tracing::error!(%error, stream_id = candidate.stream_id(), "expired PUT retirement failed");
                    return text_response(500, "expired stream retirement failed");
                }
            }

            // Retry exactly once after retirement/revalidation. A second expiry
            // result means another incarnation won the path race; ask the client
            // to retry instead of performing path-unsafe cleanup by name.
            let store2 = store.clone();
            match tokio::task::spawn_blocking(move || {
                store2.create(&path, config, parent, base_offset)
            })
            .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return retirement_busy()
                }
                Ok(Err(error)) => return text_response(500, &error.to_string()),
                Err(_) => return text_response(500, "create task failed"),
            }
        }
        result => result,
    };
    match result {
        CreateResult::Expired(_) => ResponseBuilder::new(503)
            .hs("retry-after", "1")
            .body(full("stream retirement in progress")),
        CreateResult::SourceUnavailable => text_response(409, "fork source is unavailable"),
        CreateResult::Conflict => text_response(409, "stream exists with different configuration"),
        CreateResult::Exists(st) => {
            // Store::evaluate_existing_create performed the compatible PUT's
            // TTL refresh atomically with its live/fence/configuration check.
            if st.config.ttl_seconds.is_some() {
                store.mark_meta_dirty(&st);
            }
            let t = st.tail();
            let mut b = ResponseBuilder::new(200)
                .h("content-type", st.config.content_type.clone())
                .h(H_NEXT_OFFSET, format_offset(t.bytes));
            if t.closed {
                b = b.hs(H_CLOSED, "true");
            }
            b.body(empty())
        }
        CreateResult::Created(st) => {
            let notify_subscription = wire.is_some();
            let mut append_guard = None;
            if let Some(wire) = wire {
                let lock_t0 = crate::telemetry::Timer::start();
                let mut ap = st.appender.lock().await;
                crate::telemetry::record_append_lock_wait(lock_t0.elapsed_secs());
                let append_now = SystemTime::now();
                let guard = match st.begin_append_at(append_now) {
                    Ok(guard) => guard,
                    Err(StreamAccessError::Gone) => return gone(),
                    Err(StreamAccessError::Expired) => {
                        drop(ap);
                        let candidate = store.candidate_for(&st);
                        enqueue_expired_before_not_found(&store, &candidate, append_now).await;
                        return text_response(404, "stream not found");
                    }
                };
                #[cfg(test)]
                test_support::pause_append(test_support::AppendHookPoint::AfterAdmission).await;
                let pre_written = ap.written;
                let new_tail = match write_wire(&st, &mut ap, &wire) {
                    Ok(t) => t,
                    Err(WireWriteError::Access(StreamAccessError::Gone)) => return gone(),
                    Err(WireWriteError::Access(StreamAccessError::Expired)) => {
                        return text_response(404, "stream not found")
                    }
                    Err(WireWriteError::Io) => return text_response(500, "write failed"),
                };
                let target = ap.written;
                // Read `file_base` under the appender lock so a concurrent
                // compaction that raises `file_base` + resets `ap.written` together
                // can't desync it from `target`.
                let stream_offset = wal_stream_offset(&st, target, &wire);
                // Stage to the WAL UNDER the appender lock so per-stream LSN order
                // matches byte order (see stage_for_durability); the slow
                // durability wait runs after the lock is dropped.
                let staged_lsn = match stage_for_durability(&store, &st, &wire, stream_offset) {
                    Ok(lsn) => lsn,
                    Err(_) => {
                        // ROLL BACK the data-file write: the bytes were 500'd but
                        // already sit in the file — left in place they would be
                        // durably resurrected by the next successful append /
                        // checkpoint (client told "failed", bytes served anyway).
                        let _ = ap.file.set_len(pre_written);
                        ap.written = pre_written;
                        {
                            let mut sh = st.shared.write().unwrap();
                            sh.tail = sh.file_base + pre_written;
                        }
                        return text_response(500, "wal stage failed");
                    }
                };
                drop(ap);
                if let Some(lsn) = staged_lsn {
                    wait_durable_lsn(&store, &st, lsn).await;
                }
                if !guard.may_publish() {
                    return text_response(404, "stream not found");
                }
                #[cfg(test)]
                test_support::pause_append(test_support::AppendHookPoint::BeforeTailPublication)
                    .await;
                // Durable now (wal) / page-cache written (memory): expose to readers.
                match publish_durable_tail(&store, &st, new_tail, &wire) {
                    Ok(()) => {}
                    Err(StreamAccessError::Gone) => return gone(),
                    Err(StreamAccessError::Expired) => {
                        return text_response(404, "stream not found")
                    }
                }
                #[cfg(test)]
                test_support::pause_append(test_support::AppendHookPoint::AfterPublication).await;
                append_guard = Some(guard);
            }
            if notify_subscription {
                store
                    .subscriptions
                    .clone()
                    .on_stream_append(store.clone(), &st.path)
                    .await;
            }
            let t = st.tail();
            let mut b = ResponseBuilder::new(201)
                .h(
                    "location",
                    format!(
                        "http://{}{}",
                        host.as_deref().unwrap_or("localhost"),
                        st.path
                    ),
                )
                .h("content-type", st.config.content_type.clone())
                .h(H_NEXT_OFFSET, format_offset(t.bytes));
            if t.closed {
                b = b.hs(H_CLOSED, "true");
            }
            let response = b.body(empty());
            // Keep the admission guard alive through subscription notification
            // and the final 2xx decision. Once the atomic publication won the
            // stream's shared lock, a later fence must not downgrade that
            // already-visible write to 404.
            drop(append_guard);
            response
        }
    }
}

// ---------- wire encoding (JSON flattening) ----------

/// Convert a request body into the contiguous wire-byte representation.
/// JSON: each message is the raw value followed by a `,`; arrays flatten one level.
fn encode_wire(
    body: &Bytes,
    is_json: bool,
    allow_empty_array: bool,
) -> Result<Bytes, &'static str> {
    if !is_json {
        return Ok(body.clone());
    }
    let text = std::str::from_utf8(body).map_err(|_| "invalid UTF-8 in JSON body")?;
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') {
        let elems: Vec<&RawValue> = serde_json::from_str(text).map_err(|_| "invalid JSON body")?;
        if elems.is_empty() {
            if allow_empty_array {
                return Ok(Bytes::new());
            }
            return Err("empty JSON array append");
        }
        let mut out = BytesMut::with_capacity(body.len());
        for e in &elems {
            out.put_slice(e.get().as_bytes());
            out.put_u8(b',');
        }
        Ok(out.freeze())
    } else {
        let v: &RawValue = serde_json::from_str(text).map_err(|_| "invalid JSON body")?;
        let raw = v.get();
        let mut out = BytesMut::with_capacity(raw.len() + 1);
        out.put_slice(raw.as_bytes());
        out.put_u8(b',');
        Ok(out.freeze())
    }
}

/// Fire a background sealing/offload pass for a stream after a durable append.
/// No-op when tiering is off (checked inside `maybe_seal`); never blocks the
/// append ack — the work runs on a detached task.
fn maybe_seal_bg(store: &Arc<Store>, st: &Arc<StreamState>) {
    if !store.tier_config.enabled() {
        return;
    }
    let store = store.clone();
    let st = st.clone();
    tokio::spawn(async move {
        store.maybe_seal(&st).await;
    });
}

/// Compute the logical pre-append `stream_offset` for the WAL record.
///
/// MUST be called while the caller still holds the appender lock: `file_base`
/// and `target` (`ap.written`) are reset together under that lock on compaction,
/// so reading `file_base` here keeps it consistent with the captured `target`.
fn wal_stream_offset(st: &StreamState, target: u64, wire: &Bytes) -> u64 {
    st.shared.read().unwrap().file_base + target - wire.len() as u64
}

/// Stage the append into the WAL, assigning its LSN. MUST be called while the
/// appender lock is still held, so that PER STREAM the WAL LSN order matches the
/// byte/file-write order. That ordering is load-bearing: the committer's durable
/// watermark is a CONTIGUOUS-LSN cursor, so once LSN order tracks byte order,
/// `wait_durable(lsn)` returning guarantees every lower-offset record of this
/// stream is durable too — which is exactly what `publish_durable_tail` relies on
/// when it exposes bytes up to a tail. Reserving the LSN off the appender lock
/// (as a plain `drop(ap)` before staging would) lets a later-byte append win a
/// LOWER LSN, so its `wait_durable` could fire while an earlier-byte (higher-LSN)
/// record is still un-durable — exposing a non-durable interior range.
///
/// Returns the staged LSN, or `None` in memory mode (no WAL). The durability WAIT
/// is done separately, off the lock, by `wait_durable_lsn` (the slow part).
fn stage_for_durability(
    store: &Arc<Store>,
    st: &Arc<StreamState>,
    wire: &Bytes,
    stream_offset: u64,
) -> std::io::Result<Option<u64>> {
    // memory mode: no WAL — the page-cache file write IS the ack. No fsync, no stage.
    if durability() == DurabilityMode::Memory {
        return Ok(None);
    }
    let wal = store
        .wal
        .get()
        .expect("WAL must be attached before serving");
    let shard = wal.shard_for(st.id);
    // Register the touched per-stream file into the shard's dirty set
    // (spec §7) BEFORE staging the WAL record — see the full ordering note in
    // the WAL spec. Registering first closes the recycle-before-fsync window.
    shard.register_dirty(st.id, Arc::clone(st));
    let lsn = shard.reserve_and_stage(
        crate::wal::codec::RecordKind::Append,
        st.id,
        stream_offset,
        wire,
    )?;
    Ok(Some(lsn))
}

/// Wait until `lsn` is durable (the WAL `fdatasync` has covered it). Runs OFF the
/// appender lock — only the LSN reservation (`stage_for_durability`) needs the
/// lock; the fsync wait must not serialize same-stream appenders.
async fn wait_durable_lsn(store: &Arc<Store>, st: &Arc<StreamState>, lsn: u64) {
    let wal = store
        .wal
        .get()
        .expect("WAL must be attached before serving");
    let shard = wal.shard_for(st.id);
    shard.wait_durable(lsn).await;
}

/// Write the wire bytes to the stream's own file (page cache) and advance the
/// WRITER tail `s.tail`. Returns the new logical tail. Does NOT make the bytes
/// reader-visible: visibility is published by `publish_durable_tail` only after
/// the bytes are durable (mirrors the close path's durability-before-visibility
/// ordering — PROTOCOL.md §4.1). Adds no fsync: the per-stream file stays
/// async/WAL-recoverable; the only durability barrier is the WAL `fdatasync`
/// awaited in `wait_durable_lsn`.
enum WireWriteError {
    Io,
    Access(StreamAccessError),
}

fn write_wire(st: &StreamState, ap: &mut Appender, wire: &Bytes) -> Result<u64, WireWriteError> {
    use std::io::Write;
    let pre_written = ap.written;
    if (&*ap.file).write_all(wire).is_err() {
        // A partial write (ENOSPC mid-slice) leaves garbage bytes in the file
        // PAST `ap.written` while the logical offsets don't advance — every
        // later append would land after the garbage (O_APPEND) with a logical
        // offset that assumes it landed at `ap.written`: silent, permanent
        // offset desync for all subsequent data. Truncate back to the exact
        // pre-write length so physical == logical again.
        let _ = ap.file.set_len(ap.written);
        return Err(WireWriteError::Io);
    }
    ap.written += wire.len() as u64;
    let tail = match st.with_live_shared_mut(|s| {
        let tail = s.file_base + ap.written;
        s.tail = tail;
        s.last_access = SystemTime::now();
        tail
    }) {
        Ok(tail) => tail,
        Err(error) => {
            let _ = ap.file.set_len(pre_written);
            ap.written = pre_written;
            return Err(WireWriteError::Access(error));
        }
    };
    Ok(tail)
}

/// Expose freshly-appended bytes to readers AFTER they are durable (in `wal` mode
/// `wait_durable_lsn` has awaited the WAL `fdatasync` for an LSN staged in byte
/// order; in `memory` mode there is no WAL and the page-cache write IS the ack).
/// Advances the reader-observable
/// `durable_tail` MONOTONICALLY and, only when it actually advances, refreshes the
/// tail-chunk cache and wakes live subscribers. The monotonic guard makes
/// concurrent appenders (whose group-commit fsyncs may resolve out of order)
/// safe: a later appender publishing the higher frontier first is fine (all
/// lower bytes are durable too), and the earlier appender then no-ops.
fn publish_durable_tail(
    store: &Store,
    st: &StreamState,
    tail: u64,
    wire: &Bytes,
) -> Result<(), StreamAccessError> {
    let Some(published) = st.publish_durable_tail_if_live(tail)? else {
        // A concurrent appender already published an equal/greater durable
        // frontier — nothing to expose, and re-firing would regress the watch.
        return Ok(());
    };
    // Publish the resident chunk BEFORE waking subscribers, so a long-poll/SSE
    // reader woken by the tail update reliably hits the cache (one shared copy)
    // instead of racing ahead and falling back to a file read. The chunk spans
    // [tail - wire.len(), tail).
    st.set_last_chunk(tail - wire.len() as u64, wire.clone());
    st.tail_tx.send_replace(published);
    // Inventory observes the already-published durable tail. This deliberately
    // adds no fsync to the append hot path; a generation-bound page detects
    // concurrent change and backup quiescence supplies a stable window.
    store.publish_inventory_tail(st);
    // Wake any reactor-served subscribers of this stream (no-op when none).
    #[cfg(target_os = "linux")]
    crate::sse_reactor::wake_stream(st);
    Ok(())
}

// ---------- POST (append) ----------

struct ProducerHeaders {
    id: String,
    epoch: u64,
    seq: u64,
}

fn parse_producer_headers(req: &Req) -> Result<Option<ProducerHeaders>, &'static str> {
    let id = header_str(req, H_PRODUCER_ID);
    let epoch = header_str(req, H_PRODUCER_EPOCH);
    let seq = header_str(req, H_PRODUCER_SEQ);
    match (id, epoch, seq) {
        (None, None, None) => Ok(None),
        (Some(id), Some(e), Some(s)) => {
            if id.is_empty() {
                return Err("empty Producer-Id");
            }
            let parse_int = |v: &str| -> Result<u64, &'static str> {
                if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit()) {
                    return Err("invalid producer header");
                }
                let n: u64 = v.parse().map_err(|_| "invalid producer header")?;
                if n > MAX_SAFE_INT {
                    return Err("producer header out of range");
                }
                Ok(n)
            };
            Ok(Some(ProducerHeaders {
                id: id.to_string(),
                epoch: parse_int(e)?,
                seq: parse_int(s)?,
            }))
        }
        _ => Err("producer headers must all be provided together"),
    }
}

enum ProducerOutcome {
    Accept,
    Duplicate { last_seq: u64 },
    StaleEpoch { current: u64 },
    Gap { expected: u64 },
    BadEpochStart,
}

fn validate_producer(shared: &Shared, p: &ProducerHeaders) -> ProducerOutcome {
    match shared.producers.get(&p.id) {
        None => {
            if p.seq == 0 {
                ProducerOutcome::Accept
            } else {
                ProducerOutcome::Gap { expected: 0 }
            }
        }
        Some(state) => {
            if p.epoch < state.epoch {
                ProducerOutcome::StaleEpoch {
                    current: state.epoch,
                }
            } else if p.epoch > state.epoch {
                if p.seq == 0 {
                    ProducerOutcome::Accept
                } else {
                    ProducerOutcome::BadEpochStart
                }
            } else if p.seq <= state.last_seq {
                ProducerOutcome::Duplicate {
                    last_seq: state.last_seq,
                }
            } else if p.seq == state.last_seq + 1 {
                ProducerOutcome::Accept
            } else {
                ProducerOutcome::Gap {
                    expected: state.last_seq + 1,
                }
            }
        }
    }
}

fn gone() -> Resp {
    text_response(410, "stream is deleted")
}

/// Append outcome, recorded as a bounded metric label on `ds.append.duration`.
#[derive(Clone, Copy)]
enum AppendOutcome {
    Accept,
    Dup,
    Conflict,
    Closed,
}

impl AppendOutcome {
    fn label(self) -> &'static str {
        match self {
            AppendOutcome::Accept => "accept",
            AppendOutcome::Dup => "dup",
            AppendOutcome::Conflict => "conflict",
            AppendOutcome::Closed => "closed",
        }
    }
}

async fn handle_append(store: Arc<Store>, req: Req, path: String) -> Resp {
    let t0 = crate::telemetry::Timer::start();
    // is_json comes back from the inner handler (false on the not-found path) so
    // the metric label doesn't cost a SECOND registry lookup per append — at high
    // stream cardinality each lookup is a cold walk of a million-key map.
    let (resp, outcome, is_json) = handle_append_inner(store, req, path, true).await;
    crate::telemetry::record_append(t0.elapsed_secs(), outcome.label(), is_json);
    resp
}

async fn handle_append_inner(
    store: Arc<Store>,
    req: Req,
    path: String,
    notify_subscriptions: bool,
) -> (Resp, AppendOutcome, bool) {
    use AppendOutcome::*;
    // Load-telemetry probe: bumps the in-flight gauge and records service time on
    // drop (covers every return path). No-op unless `--server-stats` is on.
    let _probe = crate::srvstats::AppendProbe::start();
    let lookup_now = SystemTime::now();
    let st = match store.lookup_at(&path, lookup_now, false) {
        StreamLookup::Live(stream) => stream,
        StreamLookup::Gone(_) => return (gone(), Conflict, false),
        StreamLookup::Missing => return (text_response(404, "stream not found"), Conflict, false),
        StreamLookup::Expired(candidate) => {
            enqueue_expired_before_not_found(&store, &candidate, lookup_now).await;
            return (text_response(404, "stream not found"), Conflict, false);
        }
    };
    let is_json = st.is_json;
    macro_rules! ret {
        ($resp:expr, $oc:expr) => {
            return ($resp, $oc, is_json)
        };
    }
    if st.shared.read().unwrap().soft_deleted {
        ret!(gone(), Conflict);
    }
    let producer = match parse_producer_headers(&req) {
        Ok(p) => p,
        Err(m) => ret!(text_response(400, m), Conflict),
    };
    let close_req = header_is_true(&req, H_CLOSED);
    let seq_header = header_str(&req, H_SEQ).map(|s| s.to_string());
    let req_ct = header_str(&req, "content-type").map(|s| s.to_string());

    let body = req.body.clone();

    if body.is_empty() && !close_req {
        ret!(text_response(400, "empty append body"), Conflict);
    }
    if !body.is_empty() {
        match &req_ct {
            None => ret!(text_response(400, "missing Content-Type"), Conflict),
            Some(ct) => {
                if media_type(ct) != media_type(&st.config.content_type) {
                    // closed check has precedence over content-type mismatch
                    let t = st.tail();
                    if t.closed && !close_req {
                        ret!(closed_conflict(t.bytes), Closed);
                    }
                    ret!(text_response(409, "content-type mismatch"), Conflict);
                }
            }
        }
    }

    let wire = if body.is_empty() {
        Bytes::new()
    } else {
        match encode_wire(&body, st.is_json, false) {
            Ok(w) => w,
            Err(m) => ret!(text_response(400, m), Conflict),
        }
    };

    // Serialize per stream: producer validation + write + state update under one
    // lock. Time the wait separately — lock contention is a key bottleneck.
    let lock_t0 = crate::telemetry::Timer::start();
    let srv_lock_t0 = std::time::Instant::now();
    let mut ap = st.appender.lock().await;
    crate::telemetry::record_append_lock_wait(lock_t0.elapsed_secs());
    crate::srvstats::record_applock_wait(srv_lock_t0.elapsed());
    let append_now = SystemTime::now();
    let append_guard = match st.begin_append_at(append_now) {
        Ok(guard) => guard,
        Err(StreamAccessError::Gone) => ret!(gone(), Conflict),
        Err(StreamAccessError::Expired) => {
            drop(ap);
            let candidate = store.candidate_for(&st);
            enqueue_expired_before_not_found(&store, &candidate, append_now).await;
            ret!(text_response(404, "stream not found"), Conflict)
        }
    };
    #[cfg(test)]
    test_support::pause_append(test_support::AppendHookPoint::AfterAdmission).await;

    // Closed checks (precedence: closed → seq regression → gap).
    {
        let s = st.shared.read().unwrap();
        if s.closed {
            // Report the durable tail to clients (never an offset a crash could
            // roll back) — same monotonicity contract as `tail()`.
            let tail = s.durable_tail;
            if close_req {
                if let Some(p) = &producer {
                    if let Some((cid, cep, cseq)) = &s.closed_by {
                        if *cid == p.id && *cep == p.epoch && *cseq == p.seq {
                            drop(s);
                            ret!(
                                ResponseBuilder::new(204)
                                    .hs(H_CLOSED, "true")
                                    .h(H_NEXT_OFFSET, format_offset(tail))
                                    .h(H_PRODUCER_EPOCH, p.epoch.to_string())
                                    .h(H_PRODUCER_SEQ, p.seq.to_string())
                                    .body(empty()),
                                Dup
                            );
                        }
                    }
                    drop(s);
                    ret!(closed_conflict(tail), Closed);
                }
                if body.is_empty() {
                    // idempotent close of an already-closed stream
                    drop(s);
                    ret!(
                        ResponseBuilder::new(204)
                            .hs(H_CLOSED, "true")
                            .h(H_NEXT_OFFSET, format_offset(tail))
                            .body(empty()),
                        Dup
                    );
                }
            }
            drop(s);
            ret!(closed_conflict(tail), Closed);
        }
    }

    // Producer validation.
    if let Some(p) = &producer {
        let outcome = {
            let s = st.shared.read().unwrap();
            validate_producer(&s, p)
        };
        match outcome {
            ProducerOutcome::Accept => {}
            ProducerOutcome::Duplicate { last_seq } => {
                // Gate Stream-Closed on the stream's ACTUAL durable-closed state
                // (what readers observe), not on the retry request's close flag.
                // This branch is past the already-closed early-return, so the
                // stream is open here unless it was closed durably in between.
                let (tail, closed) = {
                    let s = st.shared.read().unwrap();
                    (s.durable_tail, s.closed_durable)
                };
                let mut b = ResponseBuilder::new(204)
                    .h(H_NEXT_OFFSET, format_offset(tail))
                    .h(H_PRODUCER_EPOCH, p.epoch.to_string())
                    .h(H_PRODUCER_SEQ, last_seq.to_string());
                if closed {
                    b = b.hs(H_CLOSED, "true");
                }
                ret!(b.body(empty()), Dup);
            }
            ProducerOutcome::StaleEpoch { current } => {
                // Include the durable tail (matching the production Caddy server)
                // so a fenced producer learns the current offset. Spec §5.2.1
                // mandates only Producer-Epoch; Stream-Next-Offset is additive.
                let tail = st.shared.read().unwrap().durable_tail;
                ret!(
                    ResponseBuilder::new(403)
                        .h(H_PRODUCER_EPOCH, current.to_string())
                        .h(H_NEXT_OFFSET, format_offset(tail))
                        .body(full("stale producer epoch")),
                    Conflict
                );
            }
            ProducerOutcome::Gap { expected } => {
                ret!(
                    ResponseBuilder::new(409)
                        .h(H_PRODUCER_EXPECTED, expected.to_string())
                        .h(H_PRODUCER_RECEIVED, p.seq.to_string())
                        .body(full("producer sequence gap")),
                    Conflict
                );
            }
            ProducerOutcome::BadEpochStart => {
                ret!(
                    text_response(400, "new producer epoch must start at seq 0"),
                    Conflict
                );
            }
        }
    }
    // Stream-Seq (writer sequencing) regression check — after producer dedup so
    // duplicate producer requests stay idempotent (204).
    if let Some(seq) = &seq_header {
        let s = st.shared.read().unwrap();
        if let Some(last) = &s.last_seq_header {
            if seq.as_str() <= last.as_str() {
                let tail = s.durable_tail;
                drop(s);
                // Body must read "Sequence conflict" to match the reference
                // server: clients classify a 409 as a sequence conflict by the
                // word "sequence" in the message (see @durable-streams/client).
                ret!(
                    ResponseBuilder::new(409)
                        .h(H_NEXT_OFFSET, format_offset(tail))
                        .body(full("Sequence conflict")),
                    Conflict
                );
            }
        }
    }

    // Write + state updates. `new_tail` carries the writer tail to publish to
    // readers only AFTER durability (below), so a live reader never observes
    // bytes a crash could roll back (PROTOCOL.md §4.1).
    let mut new_tail = None;
    let pre_written = ap.written;
    // Pre-mutation snapshots for the stage-failure rollback below: a 500'd
    // append must leave NO trace — neither bytes (resurrected by the next
    // append/checkpoint) nor producer/seq dedup state (which would swallow the
    // client's retry as a duplicate: silent loss from the client's view).
    let (prev_tail, prev_last_access, prev_producer, prev_seq_header, prev_closed, prev_closed_by) = {
        let sh = st.shared.read().unwrap();
        (
            sh.tail,
            sh.last_access,
            producer
                .as_ref()
                .map(|p| (p.id.clone(), sh.producers.get(&p.id).cloned())),
            sh.last_seq_header.clone(),
            sh.closed,
            sh.closed_by.clone(),
        )
    };
    if !wire.is_empty() {
        match write_wire(&st, &mut ap, &wire) {
            Ok(t) => new_tail = Some(t),
            Err(WireWriteError::Access(StreamAccessError::Gone)) => ret!(gone(), Conflict),
            Err(WireWriteError::Access(StreamAccessError::Expired)) => {
                ret!(text_response(404, "stream not found"), Conflict)
            }
            Err(WireWriteError::Io) => ret!(text_response(500, "write failed"), Conflict),
        }
    }
    // Does this append change state the memory-mode sidecar must persist? Captured
    // BEFORE `seq_header` is consumed below. Producer/seq updates are idempotency
    // state; a TTL stream's sliding `last_access` must survive restart (mirrors the
    // read path, which marks dirty only for TTL streams). A plain append to a non-TTL stream changes
    // only `durable_tail`/`last_access`. In BOTH modes the durable tail is carried
    // elsewhere (memory: re-derived from the data-file length on restart; wal: the
    // checkpoint's per-shard `tails` map), and `last_access` only gates TTL — so a
    // plain non-TTL append needs no sidecar flush at all (cardinality-cliff #1).
    let meta_persist_needed =
        producer.is_some() || seq_header.is_some() || st.config.ttl_seconds.is_some();
    let state_update = st.with_live_shared_mut(|s| {
        // A body append refreshes last_access in write_wire. A close-only POST
        // has no wire bytes, but it is still a successful write operation and
        // therefore MUST slide a Stream-TTL window as well.
        if close_req && wire.is_empty() {
            s.last_access = SystemTime::now();
        }
        if let Some(p) = &producer {
            s.producers.insert(
                p.id.clone(),
                ProducerState {
                    epoch: p.epoch,
                    last_seq: p.seq,
                },
            );
        }
        if let Some(seq) = &seq_header {
            s.last_seq_header = Some(seq.clone());
        }
        if close_req {
            // Set the closed flag in memory so the durable meta capture below
            // records it, but DO NOT notify readers (tail_tx) yet. The closure
            // must be durable before any reader can observe EOF; otherwise a
            // reader could act on the close, the server could crash before the
            // closure is fsynced, and the stream would recover OPEN — a
            // monotonicity violation (PROTOCOL.md §4.1). The reader
            // notification is deferred until after write_meta_sync completes.
            s.closed = true;
            if let Some(p) = &producer {
                s.closed_by = Some((p.id.clone(), p.epoch, p.seq));
            }
        }
    });
    if let Err(error) = state_update {
        let _ = ap.file.set_len(pre_written);
        ap.written = pre_written;
        {
            let mut shared = st.shared.write().unwrap();
            shared.tail = prev_tail;
            shared.last_access = prev_last_access;
        }
        match error {
            StreamAccessError::Gone => ret!(gone(), Conflict),
            StreamAccessError::Expired => {
                ret!(text_response(404, "stream not found"), Conflict)
            }
        }
    }
    let target = ap.written;
    // Read `file_base` under the appender lock so a concurrent compaction can't desync
    // it from `target`.
    let stream_offset = wal_stream_offset(&st, target, &wire);
    // Stage to the WAL UNDER the appender lock so per-stream LSN order matches
    // byte order (see stage_for_durability). A stage failure is not durable —
    // error out (and skip the close commit below) rather than ack 2xx.
    let staged_lsn = if !wire.is_empty() {
        match stage_for_durability(&store, &st, &wire, stream_offset) {
            Ok(lsn) => lsn,
            Err(_) => {
                // ROLL BACK everything this append changed (still under the
                // appender lock, so no concurrent appender observed it):
                // 1) the data-file bytes — otherwise the next successful append
                //    advances the durable frontier over them and they are served
                //    (and checkpoint-persisted) despite the 500;
                // 2) the in-memory tail;
                // 3) producer/seq/closed state — otherwise the client's RETRY of
                //    this failed append is deduplicated as "already seen" and
                //    silently dropped.
                let _ = ap.file.set_len(pre_written);
                ap.written = pre_written;
                {
                    let mut sh = st.shared.write().unwrap();
                    sh.tail = prev_tail;
                    sh.last_access = prev_last_access;
                    if let Some((id, prev)) = &prev_producer {
                        match prev {
                            Some(ps) => {
                                sh.producers.insert(id.clone(), ps.clone());
                            }
                            None => {
                                sh.producers.remove(id);
                            }
                        }
                    }
                    sh.last_seq_header = prev_seq_header.clone();
                    sh.closed = prev_closed;
                    sh.closed_by = prev_closed_by.clone();
                }
                ret!(text_response(500, "wal stage failed"), Conflict)
            }
        }
    } else {
        None
    };
    drop(ap);

    // Wait for durability off the lock before exposing the bytes.
    if let Some(lsn) = staged_lsn {
        let dur_t0 = std::time::Instant::now();
        wait_durable_lsn(&store, &st, lsn).await;
        crate::srvstats::record_durwait(dur_t0.elapsed());
    }
    if !append_guard.may_publish() {
        ret!(text_response(404, "stream not found"), Conflict);
    }
    #[cfg(test)]
    test_support::pause_append(test_support::AppendHookPoint::BeforeTailPublication).await;

    // A successful atomic reader-visible publication is the request's
    // linearization point. Retirement may fence immediately afterwards, but it
    // cannot turn already-visible durable bytes into a 404 response.
    let mut publication_committed = false;

    // For an open append, expose durable bytes now. A body+close append waits
    // until the close metadata is durable and publishes bytes + EOF together
    // below, leaving no window where bytes are visible but the same request can
    // still lose the close race and return 404.
    if !close_req {
        if let Some(t) = new_tail {
            match publish_durable_tail(&store, &st, t, &wire) {
                Ok(()) => publication_committed = true,
                Err(StreamAccessError::Gone) => ret!(gone(), Conflict),
                Err(StreamAccessError::Expired) => {
                    ret!(text_response(404, "stream not found"), Conflict)
                }
            }
        }
    }

    // Closure ordering: WAL fsync → durable meta commit → expose the closure to
    // readers (closed_durable) and wake waiters. Readers never observe EOF for a
    // closure that is not yet durable (PROTOCOL.md §4.1).
    // Producer/access updates are debounced (documented crash window; see store::Meta).
    if close_req {
        let st2 = st.clone();
        let meta_res = tokio::task::spawn_blocking(move || write_meta_sync(&st2, true)).await;
        if !matches!(meta_res, Ok(Ok(()))) {
            ret!(text_response(500, "close not durable"), Conflict);
        }
        #[cfg(test)]
        test_support::pause_append(test_support::AppendHookPoint::BeforeClosePublication).await;
        let (tail, advanced) = match new_tail {
            Some(tail) => match st.publish_durable_tail_and_close_if_live(tail) {
                Ok(published) => published,
                Err(StreamAccessError::Gone) => ret!(gone(), Conflict),
                Err(StreamAccessError::Expired) => {
                    ret!(text_response(404, "stream not found"), Conflict)
                }
            },
            None => match st.publish_durable_close_if_live() {
                Ok(tail) => (tail, false),
                Err(StreamAccessError::Gone) => ret!(gone(), Conflict),
                Err(StreamAccessError::Expired) => {
                    ret!(text_response(404, "stream not found"), Conflict)
                }
            },
        };
        if advanced {
            st.set_last_chunk(tail.bytes - wire.len() as u64, wire.clone());
        }
        st.tail_tx.send_replace(tail);
        store.publish_inventory_tail(&st);
        #[cfg(target_os = "linux")]
        crate::sse_reactor::wake_stream(&st);
        publication_committed = true;
    }
    if publication_committed {
        #[cfg(test)]
        test_support::pause_append(test_support::AppendHookPoint::AfterPublication).await;
    }
    if !close_req && staged_lsn.is_some() {
        // WAL mode: the stream is in its shard's dirty set (register_dirty ran
        // during staging), so the ~3 s checkpoint will write the sidecar for us —
        // just mark it. This keeps the meta `File::create`+`rename` (and its
        // parent-directory rwsem, measured at ~40% of server CPU under write
        // saturation) plus a timer task OFF the per-append path. Producer/access
        // updates are already documented as a non-durable, lagging flush; the lag
        // bound moves from the 100 ms debounce to the checkpoint cadence.
        //
        // GATED (cardinality-cliff #1): only mark when the append changed state
        // the sidecar must persist — producer/seq idempotency or a sliding TTL.
        // A plain append still gets its fdatasync AND its `durable_tail` recorded
        // in the checkpoint's per-shard `tails` map (register_dirty + the
        // unconditional `persist_durable_tails`, independent of this flag) — and
        // that map, not the sidecar, is the authoritative durable-tail proof
        // recovery reconciles against (see wal/shard.rs step 3a, wal/recovery.rs).
        // `last_access` only gates TTL. So a plain non-TTL append needs no sidecar
        // rewrite here — dropping it removes the O(touched) `write_meta_sync` calls
        // that dominate the checkpoint's meta phase at high stream cardinality.
        if meta_persist_needed {
            st.meta_dirty
                .store(true, std::sync::atomic::Ordering::Release);
        }
    } else if !close_req && meta_persist_needed {
        // No WAL record staged (memory durability): no checkpoint will flush
        // the sidecar — queue it for the store-level periodic sweeper. Same
        // batched treatment the wal branch above gets from the checkpoint: no
        // per-stream timer task, no per-append sidecar rewrite (#4691).
        //
        // Only queued when the append actually changed state the sidecar must
        // persist — producer/seq idempotency or a sliding TTL. A plain append to
        // a non-TTL stream changes only `durable_tail`/`last_access`, and
        // memory-mode recovery reads NEITHER (the tail is re-derived from the
        // data-file length in `Store::new_with_tier`; `last_access` only gates
        // TTL expiry, which these streams don't have). Skipping the queue for
        // that common case removes the per-append sidecar rewrite whose cost
        // stops amortizing at high stream cardinality.
        store.mark_meta_dirty(&st);
    }
    if !wire.is_empty() {
        maybe_seal_bg(&store, &st);
    }
    if notify_subscriptions && new_tail.is_some() {
        store
            .subscriptions
            .clone()
            .on_stream_append(store.clone(), &st.path)
            .await;
    }

    if !publication_committed && !append_guard.may_publish() {
        ret!(text_response(404, "stream not found"), Conflict);
    }

    let tail = st.tail();
    let status = if producer.is_some() && !body.is_empty() {
        200
    } else {
        204
    };
    let mut b = ResponseBuilder::new(status).h(H_NEXT_OFFSET, format_offset(tail.bytes));
    if let Some(p) = &producer {
        b = b
            .h(H_PRODUCER_EPOCH, p.epoch.to_string())
            .h(H_PRODUCER_SEQ, p.seq.to_string());
    }
    if tail.closed {
        b = b.hs(H_CLOSED, "true");
    }
    let response = b.body(empty());
    if !publication_committed && !append_guard.may_publish() {
        ret!(text_response(404, "stream not found"), Conflict);
    }
    (response, Accept, is_json)
}

/// Append one pull-wake control event through the ordinary JSON append path.
/// The caller deliberately owns subscription notification: wake streams are
/// regular streams, but this internal write must not recursively re-enter the
/// subscription manager while it is delivering a wake.
pub(crate) async fn append_subscription_wake(
    store: Arc<Store>,
    path: String,
    event: serde_json::Value,
) -> bool {
    let req = Req {
        method: Method::Post,
        path: path.clone(),
        query: None,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: Bytes::from(event.to_string()),
    };
    let (response, _, _) = handle_append_inner(store, req, path, false).await;
    (200..300).contains(&response.status)
}

fn closed_conflict(tail: u64) -> Resp {
    ResponseBuilder::new(409)
        .hs(H_CLOSED, "true")
        .h(H_NEXT_OFFSET, format_offset(tail))
        .body(full("stream is closed"))
}

// ---------- reading bodies from the data file ----------

/// Describe payload range [start, end) as a response body. No I/O happens
/// here — the HTTP engine serves the segments (buffered copy, or sendfile on
/// engines that support it). JSON ranges always end on a `,` boundary; the
/// response is `[` + range-minus-comma + `]`. Logical ranges below the fork
/// base resolve through the parent chain.
/// Build a FileRange body for `[start, end)`. `hot` marks a live tail feed of
/// freshly-appended bytes (a caught-up long-poll wake), which the raw engine
/// can serve inline knowing it is page-cache resident.
async fn read_range_body(
    st: &Arc<StreamState>,
    start: u64,
    end: u64,
    hot: bool,
    live: &'static str,
    cache_hit: &mut bool,
) -> Body {
    let json = st.is_json;
    if end <= start {
        return if json { full("[]") } else { empty() };
    }
    let (data_start, data_end) = if json { (start, end - 1) } else { (start, end) };
    // Fast path: if the range is fully covered by the resident tail chunk
    // (the common caught-up / just-appended case), serve it from memory — no
    // file read, and shared across every concurrent reader of this append.
    let slice = st.tail_chunk_slice(data_start, data_end);
    *cache_hit = slice.is_some();
    crate::telemetry::record_tail_cache(slice.is_some(), live);
    if let Some(bytes) = slice {
        if json {
            let mut out = BytesMut::with_capacity(bytes.len() + 2);
            out.put_u8(b'[');
            out.put_slice(&bytes);
            out.put_u8(b']');
            return Body::Full(out.freeze());
        }
        return Body::Full(bytes);
    }
    let prefix: &'static [u8] = if json { b"[" } else { b"" };
    let suffix: &'static [u8] = if json { b"]" } else { b"" };
    // Resolve the range once. If it lands entirely on local fds (the live data
    // file and/or sealed chunk files) serve it zero-copy via Body::FileRange —
    // the only path when tiering is off, byte-for-byte the old behaviour.
    // Otherwise stream the placement-aware slices as a chunked channel so peak
    // memory stays O(segment) — one range-GET per remote segment, windowed local
    // reads — never O(read size).
    let mut slices = Vec::new();
    crate::store::resolve_range(st, data_start, data_end, &mut slices);
    match crate::store::into_local_segments(slices) {
        Ok(segments) => Body::FileRange {
            segments,
            prefix,
            suffix,
            hot,
        },
        Err(slices) => stream_resolved_body(st, slices, prefix, suffix),
    }
}

/// Outcome of sizing one read response.
enum ChunkEnd {
    /// Serve `[start, end)`. `end == tail` means nothing was capped. `body`
    /// carries the range's bytes when the sizing pass already read them, so the
    /// response is framed from those instead of resolving and reading the same
    /// range a second time.
    At { end: u64, body: Option<Bytes> },
    /// A JSON range that does not decompose into whole top-level values: the
    /// requested offset is not a value boundary (only a client-fabricated offset
    /// can be — server-minted offsets, fork points and tier cuts all land on
    /// boundaries). Serving it would emit malformed JSON, and serving it
    /// UNCAPPED — the old fallback — would also silently defeat the chunk cap
    /// and mark an unbounded response up-to-date. Fail closed instead.
    NotAValueBoundary,
    /// The boundary window could not be read (a cold-storage error or a short
    /// read). The bytes behind the response are unavailable, so the response is
    /// refused rather than framed around a range that cannot be served.
    ReadFailed,
}

/// Cap a read of `[start, tail)` at the configured maximum chunk size
/// (PROTOCOL.md §5.6: "up to a server-defined maximum chunk size"), returning
/// the end offset the response should actually carry. `tail` means nothing was
/// capped; anything smaller is a partial page whose response MUST omit
/// `Stream-Up-To-Date` and leave `Stream-Closed` to the page that reaches the
/// tail.
///
/// The cut has to keep the response well-formed. Byte streams may be cut
/// anywhere — no read, no scan, so the common capped path stays zero-copy. JSON
/// streams are stored as the wire form `value,value,…,` and are served wrapped
/// as `[ … ]` (`read_range_body` strips the final `,` via its `end - 1`
/// framing), so a JSON cut may only land just past a TOP-LEVEL comma — the same
/// value-boundary rule the tier's sealing path applies, via the same scanner.
///
/// Finding that boundary means reading the range, so the bytes are handed back
/// to be served directly: a capped JSON page is read ONCE, not once to scan and
/// once to send (which on a cold tier is an extra range read per page). The scan
/// walks forward in cap-sized windows and is resumable, so an oversize value —
/// one larger than the cap, which must be framed whole because there is no
/// smaller well-formed page — is located without re-reading what it already
/// scanned. A range that reaches the tail with no top-level boundary anywhere is
/// not an oversize value: the range itself is not value-aligned, reported as
/// `NotAValueBoundary`.
async fn chunk_capped_end(st: &Arc<StreamState>, start: u64, tail: u64) -> ChunkEnd {
    let cap = max_chunk_bytes();
    if cap == 0 || tail.saturating_sub(start) <= cap {
        return ChunkEnd::At {
            end: tail,
            body: None,
        };
    }
    if !st.is_json {
        return ChunkEnd::At {
            end: start + cap,
            body: None,
        };
    }
    let mut scan = crate::tier::JsonValueBoundaryScan::new();
    let mut buffered = BytesMut::new();
    let mut pos = start;
    let mut last_in_cap = 0u64;
    let mut first_past_cap = 0u64;
    while pos < tail {
        let window_end = (pos + cap).min(tail);
        let Ok(data) = read_range_bytes(st, pos, window_end).await else {
            return ChunkEnd::ReadFailed;
        };
        #[cfg(test)]
        BOUNDARY_SCAN_BYTES.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        scan.feed(&data, |boundary| {
            if boundary <= cap {
                last_in_cap = boundary;
                true
            } else {
                // Past the cap: this is the end of the oversize first value, and
                // no later boundary can be a better cut.
                first_past_cap = boundary;
                false
            }
        });
        buffered.put_slice(&data);
        pos = window_end;
        if last_in_cap > 0 || first_past_cap > 0 {
            break;
        }
    }
    let cut = if last_in_cap > 0 {
        last_in_cap
    } else {
        first_past_cap
    };
    if cut == 0 {
        // The whole remainder holds no top-level value separator, but the tail
        // always sits just past one — so `start` is not a boundary.
        tracing::warn!(
            stream = %st.path,
            start,
            tail,
            "JSON read offset is not a value boundary; refusing to serve a malformed page"
        );
        return ChunkEnd::NotAValueBoundary;
    }
    let mut body = buffered.freeze();
    body.truncate(cut as usize);
    ChunkEnd::At {
        end: start + cut,
        body: Some(body),
    }
}

/// Frame already-materialized wire bytes as a response body: JSON drops the
/// trailing `,` and wraps the values as an array, matching `read_range_body`.
fn framed_body(st: &StreamState, bytes: Bytes) -> Body {
    if !st.is_json {
        return Body::Full(bytes);
    }
    let inner = bytes.slice(..bytes.len().saturating_sub(1));
    let mut out = BytesMut::with_capacity(inner.len() + 2);
    out.put_u8(b'[');
    out.put_slice(&inner);
    out.put_u8(b']');
    Body::Full(out.freeze())
}

/// Map a failed sizing decision onto its response. Kept next to `ChunkEnd` so
/// both read paths refuse identically.
fn chunk_end_error(outcome: ChunkEnd) -> Resp {
    match outcome {
        ChunkEnd::At { .. } => unreachable!("only failures reach here"),
        ChunkEnd::NotAValueBoundary => text_response(
            400,
            "offset is not a JSON message boundary; re-read from a server-issued offset",
        ),
        ChunkEnd::ReadFailed => text_response(503, "stream read failed"),
    }
}

/// Per-item read window for the local parts of a streamed cold/mixed read.
/// Remote parts are already one range-GET per sealed segment (the natural unit:
/// one object = one segment, so per-segment GETs minimize object-store
/// round-trips); local parts are cheap preads, windowed here only to bound
/// memory. Together peak memory stays O(segment).
const COLD_LOCAL_WINDOW: usize = 1024 * 1024;

/// Stream pre-resolved placement-aware slices as a chunked `Body::Channel`: one
/// item per remote segment (a single range-GET) plus windowed local reads, framed
/// by `prefix`/`suffix`. Memory stays bounded regardless of how large the cold
/// range is (the failure mode of the old buffer-it-all `Body::Full` path). The
/// slices are resolved by the caller (which already opened any chunk-file fds
/// under the manifest lock), so this never re-walks the manifest.
fn stream_resolved_body(
    st: &Arc<StreamState>,
    slices: Vec<crate::store::ResolvedSlice>,
    prefix: &'static [u8],
    suffix: &'static [u8],
) -> Body {
    use crate::store::ResolvedSlice;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (tx, rx) = mpsc::channel::<Bytes>(4);
    let failed = Arc::new(AtomicBool::new(false));
    let st = st.clone();
    let failed_producer = failed.clone();
    tokio::spawn(async move {
        // Mark the stream as aborted-due-to-error so the engine drops the
        // connection (no clean chunked terminator) instead of serving a
        // well-formed but truncated response. A `tx.send` failure is the client
        // going away (not our error), so it does NOT set the flag.
        let fail = || failed_producer.store(true, Ordering::Release);
        if !prefix.is_empty() && tx.send(Bytes::from_static(prefix)).await.is_err() {
            return;
        }
        for sl in slices {
            match sl {
                ResolvedSlice::Missing => {
                    // Poison slice (unreadable sealed chunk): abort the
                    // connection — a response missing interior bytes must never
                    // terminate cleanly.
                    fail();
                    return;
                }
                ResolvedSlice::Local(seg) => {
                    // Window the (possibly large) local slice so we never hold
                    // more than COLD_LOCAL_WINDOW of it in memory at once.
                    let mut off = 0u64;
                    while off < seg.len {
                        let n = (seg.len - off).min(COLD_LOCAL_WINDOW as u64);
                        let win = Segment {
                            file: seg.file.clone(),
                            file_start: seg.file_start + off,
                            len: n,
                        };
                        let bytes =
                            tokio::task::spawn_blocking(move || materialize_segments(&[win]))
                                .await
                                .unwrap_or_default();
                        // A short read means we cannot honour the content — abort
                        // (set the flag) so the engine drops the connection rather
                        // than emitting a clean-but-truncated response.
                        if bytes.len() as u64 != n {
                            fail();
                            return;
                        }
                        if tx.send(bytes).await.is_err() {
                            return; // client gone — not our failure
                        }
                        off += n;
                    }
                }
                ResolvedSlice::Remote { key, offset, len } => {
                    let Some(bs) = &st.blobstore else {
                        fail();
                        return;
                    };
                    match bs.get_range(&key, offset, len).await {
                        // Validate the object came back at full length — a
                        // truncated cold read must abort, never be forwarded.
                        Ok(b) if b.len() as u64 == len => {
                            if tx.send(b).await.is_err() {
                                return; // client gone
                            }
                        }
                        _ => {
                            fail();
                            return;
                        }
                    }
                }
            }
        }
        if !suffix.is_empty() {
            let _ = tx.send(Bytes::from_static(suffix)).await;
        }
    });
    Body::Channel(crate::api::StreamBody { rx, failed })
}

/// Materialize pre-resolved placement-aware slices into one contiguous buffer:
/// local file segments via positioned reads, remote segments via the BlobStore,
/// spliced in offset order, framed by `prefix`/`suffix`.
async fn materialize_resolved(
    st: &Arc<StreamState>,
    slices: Vec<crate::store::ResolvedSlice>,
    prefix: &'static [u8],
    suffix: &'static [u8],
) -> std::io::Result<Bytes> {
    use crate::store::ResolvedSlice;
    use std::io::{Error, ErrorKind};
    let mut out = BytesMut::new();
    out.put_slice(prefix);
    for sl in slices {
        match sl {
            ResolvedSlice::Missing => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "sealed chunk unreadable (poison slice)",
                ));
            }
            ResolvedSlice::Local(seg) => {
                let want = seg.len;
                let bytes =
                    tokio::task::spawn_blocking(move || crate::store::materialize_segments(&[seg]))
                        .await
                        .unwrap_or_default();
                // A short local read must not be forwarded as complete.
                if bytes.len() as u64 != want {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "short local read"));
                }
                out.put_slice(&bytes);
            }
            ResolvedSlice::Remote { key, offset, len } => {
                let Some(bs) = &st.blobstore else {
                    return Err(Error::other("remote slice but no blobstore configured"));
                };
                match bs.get_range(&key, offset, len).await {
                    // Validate full length — a truncated object must not be
                    // forwarded as if complete.
                    Ok(b) if b.len() as u64 == len => out.put_slice(&b),
                    Ok(_) => {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "truncated cold object",
                        ))
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
    out.put_slice(suffix);
    Ok(out.freeze())
}

// ---------- GET (catch-up / long-poll / SSE) ----------

async fn handle_read(store: Arc<Store>, req: Req, path: String) -> Resp {
    let lookup_now = SystemTime::now();
    let st = match store.lookup_at(&path, lookup_now, true) {
        StreamLookup::Live(stream) => stream,
        StreamLookup::Gone(_) => return gone(),
        StreamLookup::Missing => return text_response(404, "stream not found"),
        StreamLookup::Expired(candidate) => {
            enqueue_expired_before_not_found(&store, &candidate, lookup_now).await;
            return text_response(404, "stream not found");
        }
    };
    // lookup_at refreshes a sliding TTL atomically with the liveness decision.
    if st.config.ttl_seconds.is_some() {
        store.mark_meta_dirty(&st); // sliding TTL must survive restarts
    }
    let q = match parse_query(req.query.as_deref()) {
        Ok(q) => q,
        Err(m) => return text_response(400, m),
    };
    let offset = match parse_offset(q.offset.as_deref()) {
        Ok(o) => o,
        Err(_) => return text_response(400, "malformed offset"),
    };
    let live = q.live.as_deref();
    if live.is_some() && q.offset.is_none() {
        return text_response(400, "offset is required for live modes");
    }
    let t0 = crate::telemetry::Timer::start();
    let mut cache_hit = false;
    let (resp, live_label) = match live {
        Some("long-poll") => (
            handle_long_poll(st, offset, q.cursor, &mut cache_hit).await,
            "long-poll",
        ),
        // SSE records its own read metric per emitted batch (streaming, no single
        // dispatch latency); the dispatch here just sets up the channel.
        Some("sse") => return handle_sse(st, offset, q.cursor),
        Some(_) => return text_response(400, "invalid live mode"),
        None => (
            handle_catchup(st, offset, &req, &mut cache_hit).await,
            "catchup",
        ),
    };
    crate::telemetry::record_read(t0.elapsed_secs(), live_label, cache_hit);
    resp
}

/// Resolved start position for a read (catch-up / long-poll / SSE).
///
/// `parse_offset` has already rejected malformed offsets with `400`. A
/// well-formed offset is always accepted here: a NUMERIC offset that is beyond
/// the current tail is treated as "caught up at the tail" (matching the Go and
/// TS reference servers), NOT a `400`. The beyond-tail behaviour is therefore
/// defined in exactly ONE place and shared by all three read paths.
struct StartResolution {
    /// Byte position to read from, clamped to the tail (never `> tail`).
    start: u64,
    /// Sentinel/no-cache read (`offset=now` or an offset at/beyond the tail):
    /// no ETag, `Cache-Control: no-store`.
    now_mode: bool,
    /// `Stream-Next-Offset` to report when the response is up-to-date. For a
    /// beyond-tail offset this is the requested offset (PROTOCOL.md §5.5).
    next_offset: u64,
}

fn resolve_start(offset: ParsedOffset, tail: u64) -> StartResolution {
    match offset {
        ParsedOffset::Start => StartResolution {
            start: 0,
            now_mode: false,
            next_offset: tail,
        },
        ParsedOffset::Now => StartResolution {
            start: tail,
            now_mode: true,
            next_offset: tail,
        },
        ParsedOffset::At(b) => {
            if b > tail {
                // Beyond-tail numeric offset: caught up at the tail. Read from
                // the tail (empty range) but report the requested offset.
                StartResolution {
                    start: tail,
                    now_mode: true,
                    next_offset: b,
                }
            } else {
                StartResolution {
                    start: b,
                    now_mode: false,
                    next_offset: b,
                }
            }
        }
    }
}

async fn handle_catchup(
    st: Arc<StreamState>,
    offset: ParsedOffset,
    req: &Req,
    cache_hit: &mut bool,
) -> Resp {
    let t = st.tail();
    let StartResolution {
        start,
        now_mode,
        next_offset,
    } = resolve_start(offset, t.bytes);
    // A catch-up read returns bytes from `start` up to the server-defined
    // maximum chunk size (PROTOCOL.md §5.6); `Stream-Next-Offset` is the cursor
    // for the client's next request. In sentinel mode the range is empty, so the
    // cap is a no-op there.
    let (end, prefetched) = match chunk_capped_end(&st, start, t.bytes).await {
        ChunkEnd::At { end, body } => (end, body),
        failure => return chunk_end_error(failure),
    };
    let partial = end < t.bytes;
    // §5.6: `Stream-Up-To-Date` MUST be present only when the response includes
    // all data available at that moment, and SHOULD NOT be present when data is
    // withheld by the chunk-size limit. `Stream-Closed` likewise belongs to the
    // page that actually reaches the final offset — a reader discovers closure
    // by requesting the next offset.
    let up_to_date = !partial;
    let closed = t.closed && !partial;
    // In sentinel mode (offset=now or a beyond-tail offset) the range is empty
    // (`start == end == tail`); report the resolved next offset — the requested
    // offset for a beyond-tail read (PROTOCOL.md §5.5). Otherwise report the
    // tail (or capped end) reached by the catch-up read.
    let reported = if now_mode { next_offset } else { end };
    // No ETag for offset=now (§10.1) — it's a tail sentinel, not a cacheable range.
    // It covers the range actually returned, so a partial page and the later
    // full-tail page never share a validator.
    let etag = (!now_mode).then(|| st.etag(start, end, closed));
    if let Some(etag) = &etag {
        if header_str(req, "if-none-match") == Some(etag.as_str()) {
            let mut b = ResponseBuilder::new(304)
                .h("etag", etag.clone())
                .h(H_NEXT_OFFSET, format_offset(reported));
            if up_to_date {
                b = b.hs(H_UP_TO_DATE, "true");
            }
            if closed {
                b = b.hs(H_CLOSED, "true");
            }
            return b.body(empty());
        }
    }
    if partial {
        crate::telemetry::record_chunk_capped("catchup");
    }
    // Catch-up read of historical bytes: not a live tail feed. A capped JSON
    // page was already read whole while locating its value boundary — serve
    // those bytes instead of resolving and reading the range again.
    let body = match prefetched {
        Some(bytes) => {
            crate::telemetry::record_tail_cache(false, "catchup");
            framed_body(&st, bytes)
        }
        None => read_range_body(&st, start, end, false, "catchup", cache_hit).await,
    };
    let mut b = ResponseBuilder::new(200)
        .h("content-type", st.config.content_type.clone())
        .h(H_NEXT_OFFSET, format_offset(reported))
        .h(
            "cache-control",
            if now_mode {
                "no-store".into()
            } else {
                CACHEABLE.to_string()
            },
        );
    if up_to_date {
        b = b.hs(H_UP_TO_DATE, "true");
    }
    if let Some(etag) = etag {
        b = b.h("etag", etag);
    }
    if closed {
        b = b.hs(H_CLOSED, "true");
    }
    b.body(body)
}

async fn handle_long_poll(
    st: Arc<StreamState>,
    offset: ParsedOffset,
    client_cursor: Option<u64>,
    cache_hit: &mut bool,
) -> Resp {
    let mut deleted = st.subscribe_deleted();
    let t0 = st.tail();
    // A beyond-tail numeric offset is treated as caught-up at the tail (see
    // `resolve_start`), so it follows the normal wait path below.
    let from = resolve_start(offset, t0.bytes).start;
    let cursor = compute_cursor(client_cursor);

    // Existing data → return immediately. This is a backlog (the consumer was
    // behind the tail), so it may include cold historical bytes: not hot.
    if from < t0.bytes {
        return long_poll_data(&st, from, t0, client_cursor, false, cache_hit).await;
    }
    if t0.closed {
        return long_poll_close(t0.bytes, cursor);
    }

    // Wait for new data / closure / timeout.
    let mut rx = st.tail_tx.subscribe();
    let deadline = Instant::now() + long_poll_timeout_dur();
    loop {
        if st.is_fenced() {
            return text_response(404, "stream not found");
        }
        let t = *rx.borrow_and_update();
        if t.bytes > from {
            // Caught-up consumer woken by new appends: freshly-written, hot.
            return long_poll_data(&st, from, t, client_cursor, true, cache_hit).await;
        }
        if t.closed {
            return long_poll_close(t.bytes, cursor);
        }
        tokio::select! {
            r = rx.changed() => {
                if r.is_err() {
                    let t = st.tail();
                    if t.bytes > from {
                        return long_poll_data(&st, from, t, client_cursor, true, cache_hit).await;
                    }
                    return long_poll_timeout(t.bytes, cursor, t.closed);
                }
            }
            _ = deleted.changed() => return text_response(404, "stream not found"),
            _ = tokio::time::sleep(deadline.saturating_duration_since(Instant::now())) => {
                // Deadline hit — but re-check the tail EXACTLY like the
                // closed-channel arm above. Returning a timeout that advertises
                // the fresh tail as `Stream-Next-Offset` while NOT delivering
                // the bytes behind it silently SKIPS data: an append whose
                // durable-tail publish lands inside the deadline window gets
                // jumped over (the client adopts the header offset from every
                // response, including empty 204s) and is never delivered.
                // Invariant: a long-poll response never advances the client's
                // offset beyond the bytes it actually delivered.
                let t = st.tail();
                if t.bytes > from {
                    return long_poll_data(&st, from, t, client_cursor, true, cache_hit).await;
                }
                return long_poll_timeout(t.bytes, cursor, t.closed);
            }
        }
    }
}

async fn long_poll_data(
    st: &Arc<StreamState>,
    from: u64,
    t: Tail,
    client_cursor: Option<u64>,
    hot: bool,
    cache_hit: &mut bool,
) -> Resp {
    let cursor = compute_cursor(client_cursor);
    // The chunk cap is a property of a READ, not of the catch-up path: a
    // long-poll that wakes on (or returns) a large backlog would otherwise
    // deliver the whole remainder in one response — the very case the cap
    // exists for, since a woken consumer is often the furthest behind. The
    // client already advances by `Stream-Next-Offset`, and omitting
    // `Stream-Up-To-Date` tells it to come straight back for the rest.
    let (end, prefetched) = match chunk_capped_end(st, from, t.bytes).await {
        ChunkEnd::At { end, body } => (end, body),
        failure => return chunk_end_error(failure),
    };
    let partial = end < t.bytes;
    let up_to_date = !partial;
    let closed = t.closed && !partial;
    if partial {
        crate::telemetry::record_chunk_capped("long-poll");
    }
    let body = match prefetched {
        Some(bytes) => {
            crate::telemetry::record_tail_cache(false, "long-poll");
            framed_body(st, bytes)
        }
        None => read_range_body(st, from, end, hot, "long-poll", cache_hit).await,
    };
    let mut b = ResponseBuilder::new(200)
        .h("content-type", st.config.content_type.clone())
        .h(H_NEXT_OFFSET, format_offset(end))
        .h(H_CURSOR, cursor.to_string())
        .h("etag", st.etag(from, end, closed))
        .hs("cache-control", CACHEABLE);
    if up_to_date {
        b = b.hs(H_UP_TO_DATE, "true");
    }
    if closed {
        b = b.hs(H_CLOSED, "true");
    }
    b.body(body)
}

fn long_poll_close(tail: u64, cursor: u64) -> Resp {
    ResponseBuilder::new(204)
        .h(H_NEXT_OFFSET, format_offset(tail))
        .h(H_CURSOR, cursor.to_string())
        .hs(H_UP_TO_DATE, "true")
        .hs(H_CLOSED, "true")
        .hs("cache-control", "no-store")
        .body(empty())
}

fn long_poll_timeout(tail: u64, cursor: u64, closed: bool) -> Resp {
    let mut b = ResponseBuilder::new(204)
        .h(H_NEXT_OFFSET, format_offset(tail))
        .h(H_CURSOR, cursor.to_string())
        .hs(H_UP_TO_DATE, "true")
        .hs("cache-control", "no-store");
    if closed {
        b = b.hs(H_CLOSED, "true");
    }
    b.body(empty())
}

// ---------- SSE ----------

#[derive(Clone, Copy)]
pub(crate) enum SseEncoding {
    Json,
    Text,
    Base64,
}

fn sse_encoding(st: &StreamState) -> SseEncoding {
    if st.is_json {
        SseEncoding::Json
    } else if media_type(&st.config.content_type).starts_with("text/") {
        SseEncoding::Text
    } else {
        SseEncoding::Base64
    }
}

/// Encode a wire byte range as one SSE `data` event in the stream's encoding.
/// Shared by the inline producer (`SseSource::next`) and the reactor so both
/// emit byte-identical frames.
pub(crate) fn sse_encode_data(out: &mut String, data: &[u8], encoding: SseEncoding) {
    match encoding {
        SseEncoding::Json => {
            // wire bytes end with ','; strip it and wrap the records as an array
            let inner = &data[..data.len().saturating_sub(1)];
            let mut payload = String::with_capacity(inner.len() + 2);
            payload.push('[');
            payload.push_str(&String::from_utf8_lossy(inner));
            payload.push(']');
            sse_data_event(out, &payload);
        }
        SseEncoding::Text => sse_data_event(out, &String::from_utf8_lossy(data)),
        SseEncoding::Base64 => sse_data_event(
            out,
            &crate::api::base64_encode(data, crate::api::BASE64_STD, true),
        ),
    }
}

/// Largest prefix of `data` that does not end in the middle of a UTF-8 sequence.
/// A `text/*` SSE frame is encoded with `from_utf8_lossy`, so a chunk-capped cut
/// through a multi-byte character would turn it into replacement characters on
/// BOTH sides of the split. Bytes that are invalid for other reasons keep
/// today's lossy behaviour.
pub(crate) fn utf8_safe_end(data: &[u8]) -> usize {
    match std::str::from_utf8(data) {
        Ok(_) => data.len(),
        // A truncated final sequence (`error_len() == None`) is exactly the cut
        // we are allowed to move; anything else is pre-existing invalid input.
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        Err(_) => data.len(),
    }
}

/// Write `payload` as one SSE `data` event, splitting on line terminators to
/// prevent `data:` injection.
pub(crate) fn sse_data_event(out: &mut String, payload: &str) {
    out.push_str("event: data\n");
    for line in payload.split(['\n', '\r']) {
        out.push_str("data:");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
}

pub(crate) fn sse_control_event(
    out: &mut String,
    next: u64,
    cursor: u64,
    up_to_date: bool,
    closed: bool,
) {
    out.push_str("event: control\n");
    out.push_str("data:{\"streamNextOffset\":\"");
    out.push_str(&format_offset(next));
    out.push('"');
    if !closed {
        out.push_str(",\"streamCursor\":\"");
        out.push_str(&cursor.to_string());
        out.push('"');
    }
    if up_to_date {
        out.push_str(",\"upToDate\":true");
    }
    if closed {
        out.push_str(",\"streamClosed\":true");
    }
    out.push_str("}\n\n");
}

/// Inline SSE producer state. Driven by the connection task via `EventSource`
/// (one `next_chunk` call per emitted SSE event) instead of a spawned task
/// feeding an mpsc channel: an idle subscriber then costs only its connection,
/// not an extra task future + channel buffer (the per-subscriber memory that
/// made fan-out grow linearly). All caught-up subscribers still share the one
/// resident tail chunk, so the fan-out read stays O(1).
struct SseSource {
    st: Arc<StreamState>,
    rxw: tokio::sync::watch::Receiver<Tail>,
    deleted: tokio::sync::watch::Receiver<bool>,
    pos: u64,
    start: u64,
    deadline: Instant,
    client_cursor: Option<u64>,
    encoding: SseEncoding,
    sent_initial: bool,
    done: bool,
}

impl SseSource {
    /// Produce the next SSE event, or `None` to end the stream. Mirrors the
    /// original producer loop, but returns one frame per call (state persists in
    /// `self`) so it can run inline without a channel.
    async fn next(&mut self) -> Option<Bytes> {
        if self.done {
            return None;
        }
        loop {
            if self.st.is_fenced() {
                self.done = true;
                return None;
            }
            let t = *self.rxw.borrow_and_update();
            if t.bytes > self.pos {
                // One event carries at most the read chunk cap. SSE is already an
                // incremental framing, but a subscriber starting at `offset=0` (or
                // reconnecting far behind the tail) would otherwise materialize
                // and encode the whole backlog in one frame — the same unbounded
                // read memory the cap exists to prevent. A capped batch simply
                // leaves `pos` short of the tail, so `up_to_date`/`closed_now`
                // stay false and the next call emits the following batch.
                let (end, prefetched) = match chunk_capped_end(&self.st, self.pos, t.bytes).await {
                    ChunkEnd::At { end, body } => (end, body),
                    // Unreadable or not value-aligned: end the stream without
                    // advancing `pos`, exactly like a failed read below.
                    _ => {
                        self.done = true;
                        return None;
                    }
                };
                if end < t.bytes {
                    crate::telemetry::record_chunk_capped("sse");
                }
                // Read new range and emit data + control. Caught-up subscribers
                // share the resident tail chunk — one read for all of them —
                // and fall back to a file read only when behind it.
                let read_t0 = crate::telemetry::Timer::start();
                let cache_hit;
                let data = match prefetched {
                    // Already read while locating the batch's value boundary.
                    Some(bytes) => {
                        cache_hit = false;
                        bytes
                    }
                    None => match self.st.tail_chunk_slice(self.pos, end) {
                        Some(b) => {
                            cache_hit = true;
                            b
                        }
                        None => {
                            cache_hit = false;
                            match read_range_bytes(&self.st, self.pos, end).await {
                                Ok(d) => d,
                                // End the stream without advancing `pos`: the client
                                // reconnects from its last offset, never skipping a gap.
                                Err(_) => {
                                    self.done = true;
                                    return None;
                                }
                            }
                        }
                    },
                };
                crate::telemetry::record_tail_cache(cache_hit, "sse");
                crate::telemetry::record_read(read_t0.elapsed_secs(), "sse", cache_hit);
                // A capped `text/*` frame must not split a UTF-8 character.
                let (data, end) = match self.encoding {
                    SseEncoding::Text if end < t.bytes => {
                        let safe = utf8_safe_end(&data);
                        if safe == 0 {
                            (data, end)
                        } else {
                            (data.slice(..safe), self.pos + safe as u64)
                        }
                    }
                    _ => (data, end),
                };
                let mut ev = String::new();
                sse_encode_data(&mut ev, &data, self.encoding);
                self.pos = end;
                let up_to_date = self.pos >= self.st.tail().bytes;
                // If the stream closed atomically with this final data, fold the
                // close into this control event (streamClosed:true) rather than
                // emitting a plain up-to-date control followed by a separate close
                // event — the reference server / TS client expect the close signal
                // on the control immediately after the final data.
                let closed_now = t.closed && self.pos >= t.bytes;
                sse_control_event(
                    &mut ev,
                    self.pos,
                    compute_cursor(self.client_cursor),
                    up_to_date,
                    closed_now,
                );
                if closed_now {
                    self.done = true;
                }
                return Some(Bytes::from(ev));
            }
            if t.closed && self.pos >= t.bytes {
                let mut ev = String::new();
                sse_control_event(
                    &mut ev,
                    self.pos,
                    compute_cursor(self.client_cursor),
                    true,
                    true,
                );
                self.done = true;
                return Some(Bytes::from(ev));
            }
            // Initial control event when starting caught-up (once).
            if !self.sent_initial
                && self.pos == self.start
                && t.bytes == self.start
                && !t.closed
                && self.pos == self.st.tail().bytes
            {
                let mut ev = String::new();
                sse_control_event(
                    &mut ev,
                    self.pos,
                    compute_cursor(self.client_cursor),
                    true,
                    false,
                );
                self.sent_initial = true;
                return Some(Bytes::from(ev));
            }
            // Idle wait: bounded by the total SSE duration, but woken early by new
            // data and broken into keep-alive intervals so an idle stream still
            // emits a periodic up-to-date control (liveness for proxies/clients).
            let now = Instant::now();
            if now >= self.deadline {
                self.done = true;
                return None; // total cap reached; client reconnects
            }
            let wait = SSE_KEEPALIVE.min(self.deadline - now);
            tokio::select! {
                r = self.rxw.changed() => {
                    if r.is_err() {
                        self.done = true;
                        return None;
                    }
                }
                _ = self.deleted.changed() => {
                    self.done = true;
                    return None;
                }
                _ = tokio::time::sleep(wait) => {
                    // No new data within the keep-alive window: emit a heartbeat
                    // control (still open here — the close path returns above).
                    let mut ev = String::new();
                    sse_control_event(&mut ev, self.pos, compute_cursor(self.client_cursor), true, false);
                    return Some(Bytes::from(ev));
                }
            }
        }
    }
}

impl crate::api::EventSource for SseSource {
    fn next_chunk(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Bytes>> + Send + '_>> {
        Box::pin(self.next())
    }

    /// Live-tail subscribers (root stream, tiering off, start at/after the live
    /// file base) are served by the epoll reactor: the connection task hands off
    /// the socket and frees its future. Everything else (cold catch-up from a
    /// forked/compacted/tiered range) stays on the inline hand-off path.
    #[cfg(target_os = "linux")]
    fn reactor_reg(&self) -> Option<crate::api::SseReg> {
        if self.st.parent.is_some() || self.st.blobstore.is_some() {
            return None;
        }
        if self.start < self.st.shared.read().unwrap().file_base {
            return None;
        }
        Some(crate::api::SseReg {
            st: self.st.clone(),
            start: self.start,
            encoding: self.encoding,
            client_cursor: self.client_cursor,
        })
    }
}

fn handle_sse(st: Arc<StreamState>, offset: ParsedOffset, client_cursor: Option<u64>) -> Resp {
    let t0 = st.tail();
    // A beyond-tail numeric offset starts caught-up at the tail (see
    // `resolve_start`): emit the initial up-to-date control event, then wait.
    let start = resolve_start(offset, t0.bytes).start;
    let encoding = sse_encoding(&st);
    let is_b64 = matches!(encoding, SseEncoding::Base64);

    let src = SseSource {
        rxw: st.tail_tx.subscribe(),
        deleted: st.subscribe_deleted(),
        st,
        pos: start,
        start,
        deadline: Instant::now() + SSE_MAX_DURATION,
        client_cursor,
        encoding,
        sent_initial: false,
        done: false,
    };

    let mut b = ResponseBuilder::new(200)
        .hs("content-type", "text/event-stream")
        .hs("cache-control", "no-cache")
        // SSE responses are single-use: the server unilaterally closes the socket
        // when the stream closes (or at SSE_MAX_DURATION), so we must NOT advertise
        // keep-alive. If we did, the client (e.g. undici) would return the socket to
        // its pool and pipeline the next request onto it; the server's close() would
        // then see unread request bytes in the recv buffer and send a RST instead of
        // a FIN, discarding the still-in-flight SSE response (data + close frames)
        // and surfacing as an UND_ERR_SOCKET "other side closed" on the client.
        .hs("connection", "close");
    if is_b64 {
        b = b.hs(H_SSE_ENCODING, "base64");
    }
    // SSE is a live feed driven inline on the connection task: a mid-stream
    // hiccup just ends the event stream and the client reconnects from its last
    // offset, so there is no abort signal here.
    b.body(Body::Sse(Box::new(src)))
}

/// Read a logical byte range fully into memory (SSE batches are small).
/// Returns `Err` if the range could not be fully materialized (a short local
/// read or a cold-storage error/truncation) so callers never advance past a gap.
async fn read_range_bytes(st: &Arc<StreamState>, start: u64, end: u64) -> std::io::Result<Bytes> {
    let want = end.saturating_sub(start) as usize;
    let mut slices = Vec::new();
    crate::store::resolve_range(st, start, end, &mut slices);
    let out = match crate::store::into_local_segments(slices) {
        // Local-only fast path (always the case with tiering off): one blocking
        // read across all local segments.
        Ok(segs) => tokio::task::spawn_blocking(move || materialize_segments(&segs))
            .await
            .unwrap_or_default(),
        Err(slices) => materialize_resolved(st, slices, b"", b"").await?,
    };
    if out.len() != want {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "short read while materializing range",
        ));
    }
    Ok(out)
}

// ---------- HEAD ----------

async fn handle_head(store: Arc<Store>, path: String) -> Resp {
    let lookup_now = SystemTime::now();
    let st = match store.lookup_at(&path, lookup_now, false) {
        StreamLookup::Live(stream) => stream,
        StreamLookup::Gone(_) => return gone(),
        StreamLookup::Missing => return text_response(404, "stream not found"),
        StreamLookup::Expired(candidate) => {
            enqueue_expired_before_not_found(&store, &candidate, lookup_now).await;
            return text_response(404, "stream not found");
        }
    };
    // HEAD must not reset the TTL.
    let t = st.tail();
    let mut b = ResponseBuilder::new(200)
        .h("content-type", st.config.content_type.clone())
        .h(H_NEXT_OFFSET, format_offset(t.bytes))
        .hs("cache-control", "no-store");
    if let Some(ttl) = st.config.ttl_seconds {
        b = b.h(H_TTL, ttl.to_string());
    }
    if let Some(raw) = &st.config.expires_at_raw {
        b = b.h(H_EXPIRES_AT, raw.clone());
    }
    if t.closed {
        b = b.hs(H_CLOSED, "true");
    }
    b.body(empty())
}

// ---------- DELETE ----------

async fn handle_delete(store: Arc<Store>, path: String) -> Resp {
    let now = SystemTime::now();
    let candidate = match store.lookup_at(&path, now, false) {
        StreamLookup::Missing => return text_response(404, "stream not found"),
        StreamLookup::Gone(_) => return gone(),
        StreamLookup::Live(stream) => store.candidate_for(&stream),
        StreamLookup::Expired(candidate) => {
            if candidate.stream().is_expired_at(now) {
                enqueue_expired_before_not_found(&store, &candidate, now).await;
                return text_response(404, "stream not found");
            }
            candidate
        }
    };

    match coordinated_retire_and_wait(&store, &candidate, RetirementDurability::Explicit).await {
        Ok(crate::expiry_reaper::CoordinatedOutcome::Retired(_)) => {
            ResponseBuilder::new(204).body(empty())
        }
        Ok(crate::expiry_reaper::CoordinatedOutcome::Gone) => gone(),
        Ok(crate::expiry_reaper::CoordinatedOutcome::Stale) => {
            text_response(404, "stream not found")
        }
        Ok(crate::expiry_reaper::CoordinatedOutcome::Renewed) => retirement_busy(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => retirement_busy(),
        Err(error) => {
            tracing::error!(%error, stream_id = candidate.stream_id(), "stream retirement failed");
            text_response(500, "delete not durable")
        }
    }
}

#[cfg(test)]
mod admin_inventory_tests {
    use super::*;
    use crate::api::Body;
    use crate::store::{CreateResult, Store, StreamConfig};
    use crate::tier::TierConfig;

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

    #[test]
    fn inventory_cursor_is_canonical_and_round_trips_delimiters_and_unicode() {
        let dir = std::env::temp_dir().join(format!("ds-inventory-cursor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        for path in ["a&equals=one", "é/next"] {
            assert!(matches!(
                store.create(path, stream_config(), None, 0).unwrap(),
                CreateResult::Created(_)
            ));
        }
        let first = inventory_response(&store, Some("limit=1"));
        let Body::Full(first) = first.body else {
            panic!("inventory must be a fixed JSON response")
        };
        let first: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(first["streams"][0]["path"], "a&equals=one");
        let cursor = first["next_cursor"].as_str().unwrap();
        assert_eq!(cursor, "2.a%26equals%3Done");
        let second = inventory_response(&store, Some(&format!("limit=1&cursor={cursor}")));
        let Body::Full(second) = second.body else {
            panic!("inventory must be a fixed JSON response")
        };
        let second: serde_json::Value = serde_json::from_slice(&second).unwrap();
        assert_eq!(second["streams"][0]["path"], "é/next");
        assert_eq!(
            inventory_response(&store, Some("cursor=2.a%26equals%3done")).status,
            400,
            "non-canonical escape spelling is rejected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn encoded_admin_alias_is_reserved_for_every_stream_verb() {
        let dir = std::env::temp_dir().join(format!("ds-admin-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        for method in [
            Method::Put,
            Method::Get,
            Method::Post,
            Method::Head,
            Method::Delete,
        ] {
            let response = handle(
                Arc::clone(&store),
                Req {
                    method,
                    path: "/_admin%2Fuser-stream".into(),
                    query: None,
                    headers: vec![("stream-closed".into(), "true".into())],
                    body: bytes::Bytes::new(),
                },
            )
            .await;
            assert_eq!(response.status, 400, "{method:?}");
        }
        let response = handle(
            Arc::clone(&store),
            Req {
                method: Method::Put,
                path: "/%5Fadmin%2Fuser-stream".into(),
                query: None,
                headers: vec![],
                body: bytes::Bytes::new(),
            },
        )
        .await;
        assert_eq!(response.status, 400);
        assert!(store.get("/_admin/user-stream").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn close_publication_marks_inventory_closed_after_durable_close() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = std::env::temp_dir().join(format!("ds-inventory-close-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        for path in ["close-only", "append-close"] {
            let created = handle(
                Arc::clone(&store),
                Req {
                    method: Method::Put,
                    path: path.into(),
                    query: None,
                    headers: vec![("content-type".into(), "application/octet-stream".into())],
                    body: bytes::Bytes::new(),
                },
            )
            .await;
            assert_eq!(created.status, 201);
        }
        let close = handle(
            Arc::clone(&store),
            Req {
                method: Method::Post,
                path: "close-only".into(),
                query: None,
                headers: vec![
                    ("content-type".into(), "application/octet-stream".into()),
                    ("stream-closed".into(), "true".into()),
                ],
                body: bytes::Bytes::new(),
            },
        )
        .await;
        assert_eq!(close.status, 204);
        let append_close = handle(
            Arc::clone(&store),
            Req {
                method: Method::Post,
                path: "append-close".into(),
                query: None,
                headers: vec![
                    ("content-type".into(), "application/octet-stream".into()),
                    ("stream-closed".into(), "true".into()),
                ],
                body: bytes::Bytes::from_static(b"abc"),
            },
        )
        .await;
        assert_eq!(append_close.status, 204);
        let (_, entries, _) = store.inventory_page(None, None, 10).unwrap();
        let only = entries
            .iter()
            .find(|entry| entry.path == "close-only")
            .unwrap();
        assert!(only.closed && only.durable_bytes == 0);
        let appended = entries
            .iter()
            .find(|entry| entry.path == "append-close")
            .unwrap();
        assert!(appended.closed && appended.durable_bytes == 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inventory_generation_change_requires_pagination_restart() {
        let dir =
            std::env::temp_dir().join(format!("ds-inventory-conflict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        store.create("a", stream_config(), None, 0).unwrap();
        store.create("c", stream_config(), None, 0).unwrap();
        let first = inventory_response(&store, Some("limit=1"));
        let Body::Full(first) = first.body else {
            panic!()
        };
        let cursor = serde_json::from_slice::<serde_json::Value>(&first).unwrap()["next_cursor"]
            .as_str()
            .unwrap()
            .to_string();
        store.create("b", stream_config(), None, 0).unwrap();
        assert_eq!(
            inventory_response(&store, Some(&format!("cursor={cursor}"))).status,
            409
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expiry_admin_status_is_absent_without_a_process_coordinator() {
        if crate::expiry_reaper::status().is_none() {
            assert_eq!(expiry_status_response().status, 404);
        }
    }
}

#[cfg(test)]
mod bug1_tests {
    //! Regression for BUG-1: a cold-tier read that errors or returns a truncated
    //! object must set the `StreamBody.failed` abort flag (so engines drop the
    //! connection) instead of completing a clean-but-short chunked 200 — which
    //! would let a client resume past `stream-next-offset` and silently skip the
    //! gap. Found by the madsim DST harness.
    use super::*;
    use crate::blobstore::{BlobStore, BoxFuture};
    use crate::store::{CreateResult, ResolvedSlice, Store, StreamConfig};
    use crate::tier::TierConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy)]
    enum Mode {
        Full,
        Truncate,
        Error,
    }

    struct TestBlob(Mode);
    impl BlobStore for TestBlob {
        fn put<'a>(&'a self, _k: &'a str, _b: bytes::Bytes) -> BoxFuture<'a, std::io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn get_range<'a>(
            &'a self,
            _k: &'a str,
            _s: u64,
            len: u64,
        ) -> BoxFuture<'a, std::io::Result<bytes::Bytes>> {
            let mode = self.0;
            Box::pin(async move {
                match mode {
                    Mode::Full => Ok(bytes::Bytes::from(vec![b'x'; len as usize])),
                    // one byte short of the requested length
                    Mode::Truncate => Ok(bytes::Bytes::from(vec![
                        b'x';
                        len.saturating_sub(1) as usize
                    ])),
                    Mode::Error => Err(std::io::Error::other("cold backend boom")),
                }
            })
        }
        fn head<'a>(&'a self, _k: &'a str) -> BoxFuture<'a, std::io::Result<Option<u64>>> {
            Box::pin(async { Ok(None) })
        }
        fn delete<'a>(&'a self, _k: &'a str) -> BoxFuture<'a, std::io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn stream_cfg() -> StreamConfig {
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

    /// Drive `stream_resolved_body` over a single 100-byte Remote slice backed by
    /// a `TestBlob` in `mode`; return (bytes delivered, failed-flag).
    async fn run(mode: Mode) -> (usize, bool) {
        // Store layout/durability knobs are process-global startup settings.
        // Serialize with the lane-layout WAL tests that temporarily change
        // them, otherwise a parallel Store::new can observe the wrong lane
        // count and fail nondeterministically.
        let _guard = test_support::DurabilityGuard::wal();
        let dir = std::env::temp_dir().join(format!(
            "ds-bug1-{}-{}",
            std::process::id(),
            NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        store.blobstore = Some(Arc::new(TestBlob(mode)));
        let store = Arc::new(store);
        let st = match store.create("s", stream_cfg(), None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };
        let slices = vec![ResolvedSlice::Remote {
            key: "k".into(),
            offset: 0,
            len: 100,
        }];
        let body = stream_resolved_body(&st, slices, b"", b"");
        let (n, failed) = match body {
            Body::Channel(sb) => {
                let mut rx = sb.rx;
                let mut n = 0usize;
                while let Some(b) = rx.recv().await {
                    n += b.len();
                }
                (n, sb.failed.load(Ordering::Acquire))
            }
            _ => panic!("expected a channel body"),
        };
        let _ = std::fs::remove_dir_all(&dir);
        (n, failed)
    }

    #[tokio::test]
    async fn cold_read_full_is_not_flagged() {
        let (n, failed) = run(Mode::Full).await;
        assert!(
            !failed,
            "a full-length cold read must not be flagged failed"
        );
        assert_eq!(n, 100, "the full body is delivered");
    }

    #[tokio::test]
    async fn cold_read_truncated_aborts() {
        let (_n, failed) = run(Mode::Truncate).await;
        assert!(
            failed,
            "a truncated cold read must set the abort flag (BUG-1)"
        );
    }

    #[tokio::test]
    async fn cold_read_error_aborts() {
        let (_n, failed) = run(Mode::Error).await;
        assert!(
            failed,
            "a cold-read backend error must set the abort flag (BUG-1)"
        );
    }

    /// H4: the buffered cold-read path (`materialize_resolved` via
    /// `read_range_bytes`, used by SSE and fork sub-offset) must surface a
    /// truncated/errored cold read as `Err` — not silently return short bytes
    /// that a caller would treat as a complete (advanced) read.
    async fn run_buffered(mode: Mode) -> std::io::Result<bytes::Bytes> {
        let _guard = test_support::DurabilityGuard::wal();
        let dir = std::env::temp_dir().join(format!(
            "ds-h4-{}-{}",
            std::process::id(),
            NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        store.blobstore = Some(Arc::new(TestBlob(mode)));
        let store = Arc::new(store);
        let st = match store.create("s", stream_cfg(), None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };
        let slices = vec![ResolvedSlice::Remote {
            key: "k".into(),
            offset: 0,
            len: 100,
        }];
        let res = materialize_resolved(&st, slices, b"", b"").await;
        let _ = std::fs::remove_dir_all(&dir);
        res
    }

    #[tokio::test]
    async fn buffered_cold_read_full_ok() {
        let r = run_buffered(Mode::Full).await;
        assert_eq!(r.unwrap().len(), 100, "a full cold read returns the bytes");
    }

    #[tokio::test]
    async fn buffered_cold_read_truncated_errors() {
        assert!(
            run_buffered(Mode::Truncate).await.is_err(),
            "a truncated cold object must surface as Err (H4)"
        );
    }

    #[tokio::test]
    async fn buffered_cold_read_backend_error_errors() {
        assert!(
            run_buffered(Mode::Error).await.is_err(),
            "a cold-read backend error must surface as Err (H4)"
        );
    }
}

#[cfg(test)]
mod memory_mode_tests {
    //! Tests for `--durability memory` mode: append acks with no WAL attached.
    use super::*;
    use crate::api::{Method, Req};
    use crate::store::Store;
    use crate::tier::TierConfig;
    use bytes::Bytes;

    fn tmp(tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let p = std::env::temp_dir().join(format!(
            "ds-mem-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn put_req(path: &str, content_type: &str) -> Req {
        Req {
            method: Method::Put,
            path: path.to_string(),
            query: None,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: Bytes::new(),
        }
    }

    fn post_req(path: &str, content_type: &str, body: &[u8]) -> Req {
        Req {
            method: Method::Post,
            path: path.to_string(),
            query: None,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: Bytes::copy_from_slice(body),
        }
    }

    #[tokio::test]
    async fn memory_mode_append_acks_without_wal() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("mem-append");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        // NOTE: no WAL attached (store.wal not set) — memory mode must not touch it.

        // Create the stream (PUT).
        let resp = handle(
            Arc::clone(&store),
            put_req("m/s", "application/octet-stream"),
        )
        .await;
        assert!(
            (200..300).contains(&resp.status),
            "create stream expected 2xx, got {}",
            resp.status
        );

        // Append a record (POST) — must ack without WAL.
        let resp = handle(
            Arc::clone(&store),
            post_req("m/s", "application/octet-stream", b"hello-memory"),
        )
        .await;
        assert!(
            (200..300).contains(&resp.status),
            "memory append should ack, got {}",
            resp.status
        );

        // Verify the bytes landed in the per-stream file.
        let st = store.get("m/s").unwrap();
        assert_eq!(
            std::fs::read(&st.file_path).unwrap(),
            b"hello-memory",
            "per-stream file must hold the appended bytes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #4691: a memory-mode append must NOT flush the meta sidecar via a
    /// per-stream debounced timer (100 ms sleep + spawn_blocking per stream —
    /// ~5x wal-mode CPU at high stream cardinality). It only marks the stream
    /// dirty; the store-level periodic sweeper writes the sidecar in batch,
    /// mirroring wal mode's checkpoint treatment from #4675.
    #[tokio::test]
    async fn memory_append_defers_sidecar_to_store_sweep() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("mem-sweep");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        let resp = handle(
            Arc::clone(&store),
            put_req("m/s", "application/octet-stream"),
        )
        .await;
        assert!((200..300).contains(&resp.status), "create: {}", resp.status);

        // Append with a producer so the pending sidecar change is observable.
        let mut req = post_req("m/s", "application/octet-stream", b"payload");
        req.headers.push(("producer-id".into(), "p1".into()));
        req.headers.push(("producer-epoch".into(), "1".into()));
        req.headers.push(("producer-seq".into(), "0".into()));
        let resp = handle(Arc::clone(&store), req).await;
        assert!((200..300).contains(&resp.status), "append: {}", resp.status);

        // Well past the old 100 ms debounce: the sidecar must still be
        // unwritten — no per-append timer task may exist anymore.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let st = store.get("m/s").unwrap();
        let meta: crate::store::Meta =
            serde_json::from_slice(&std::fs::read(crate::store::meta_path(&st.file_path)).unwrap())
                .unwrap();
        assert!(
            !meta.producers.contains_key("p1"),
            "sidecar was flushed per-append (debounce timer still active)"
        );

        // The batched store sweep is what persists it.
        let flushed = tokio::task::spawn_blocking({
            let store = Arc::clone(&store);
            move || store.sweep_meta_once()
        })
        .await
        .unwrap();
        assert_eq!(flushed, 1, "the appended stream is swept");
        let meta: crate::store::Meta =
            serde_json::from_slice(&std::fs::read(crate::store::meta_path(&st.file_path)).unwrap())
                .unwrap();
        assert!(
            meta.producers.contains_key("p1"),
            "sweep must persist the pending producer state"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cardinality-cliff fix (#1): a PLAIN append (no producer/seq, non-TTL
    /// stream) in memory mode must NOT queue a sidecar flush. The tail is
    /// recovered from the data-file length and `last_access` only gates TTL, so
    /// the per-append sidecar rewrite is pure overhead whose cost stops
    /// amortizing at high stream cardinality. Contrast
    /// `memory_append_defers_sidecar_to_store_sweep`, which uses a producer
    /// append and therefore still marks dirty.
    #[tokio::test]
    async fn memory_plain_append_skips_sidecar_flush() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("mem-plain-noflush");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        let resp = handle(
            Arc::clone(&store),
            put_req("m/p", "application/octet-stream"),
        )
        .await;
        assert!((200..300).contains(&resp.status), "create: {}", resp.status);
        // Drain anything the create queued so we measure only the append's effect.
        let store2 = Arc::clone(&store);
        let _ = tokio::task::spawn_blocking(move || store2.sweep_meta_once())
            .await
            .unwrap();

        // Plain append: no producer headers, non-TTL stream.
        let resp = handle(
            Arc::clone(&store),
            post_req("m/p", "application/octet-stream", b"payload"),
        )
        .await;
        assert!((200..300).contains(&resp.status), "append: {}", resp.status);

        let flushed = tokio::task::spawn_blocking({
            let store = Arc::clone(&store);
            move || store.sweep_meta_once()
        })
        .await
        .unwrap();
        assert_eq!(
            flushed, 0,
            "a plain non-TTL memory-mode append must not queue a sidecar flush"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Long-poll deadline/data race (conformance flake root cause): a long-poll
    /// response must NEVER advance `Stream-Next-Offset` past the client's `from`
    /// without delivering the bytes in between — otherwise an append whose
    /// durable-tail publish lands inside the deadline window is advertised but
    /// not sent, and the client skips it forever. This drives many iterations of
    /// an append racing a long-poll whose deadline is aligned with the append
    /// (the conformance suite's exact shape, tightened) and asserts the
    /// invariant on every response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn long_poll_timeout_never_skips_observed_data() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        crate::handlers::set_long_poll_timeout(20);
        let dir = tmp("lp-race");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        let resp = handle(
            Arc::clone(&store),
            put_req("lp/r", "application/octet-stream"),
        )
        .await;
        assert!((200..300).contains(&resp.status), "create: {}", resp.status);

        let next_offset = |r: &crate::api::Resp| -> u64 {
            r.headers
                .iter()
                .find(|(k, _)| *k == "stream-next-offset")
                .map(|(_, v)| v.rsplit('_').next().unwrap().parse().unwrap())
                .unwrap_or(0)
        };
        let mut from: u64 = 0;
        for i in 0..200u32 {
            // Long-poll from the current offset...
            let lp = tokio::spawn(handle(
                Arc::clone(&store),
                Req {
                    method: Method::Get,
                    path: "lp/r".to_string(),
                    query: Some(format!("live=long-poll&offset={:016}_{:016}", 0, from)),
                    headers: vec![],
                    body: Bytes::new(),
                },
            ));
            // ...and race an append onto the deadline (spread over the window).
            tokio::time::sleep(std::time::Duration::from_millis(15 + (i % 10) as u64)).await;
            let ar = handle(
                Arc::clone(&store),
                post_req("lp/r", "application/octet-stream", b"x"),
            )
            .await;
            assert!((200..300).contains(&ar.status), "append: {}", ar.status);
            let r = lp.await.unwrap();
            let next = next_offset(&r);
            let has_body = !matches!(r.body, crate::api::Body::Empty);
            assert!(
                has_body || next <= from,
                "iteration {i}: empty long-poll response advanced the offset \
                 {from} -> {next} without delivering data (status {})",
                r.status
            );
            // Catch up for the next round.
            from = from.max(next);
            if !has_body && next == from {
                // ensure we don't fall behind the appends
                let t_resp = handle(
                    Arc::clone(&store),
                    Req {
                        method: Method::Get,
                        path: "lp/r".to_string(),
                        query: Some(format!("offset={:016}_{:016}", 0, from)),
                        headers: vec![],
                        body: Bytes::new(),
                    },
                )
                .await;
                from = from.max(next_offset(&t_resp));
            }
        }

        crate::handlers::set_long_poll_timeout(30_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deletion_wakes_a_caught_up_long_poll_as_not_found() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("lp-delete-wake");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        assert_eq!(
            handle(
                Arc::clone(&store),
                put_req("lp/deleted", "application/octet-stream"),
            )
            .await
            .status,
            201
        );

        let waiting = tokio::spawn(handle(
            Arc::clone(&store),
            Req {
                method: Method::Get,
                path: "lp/deleted".into(),
                query: Some("live=long-poll&offset=0000000000000000_0000000000000000".into()),
                headers: vec![],
                body: Bytes::new(),
            },
        ));
        // Let the read subscribe to the stream's sticky deletion signal.
        tokio::task::yield_now().await;

        assert_eq!(
            handle(
                Arc::clone(&store),
                Req {
                    method: Method::Delete,
                    path: "lp/deleted".into(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            204
        );

        let response = tokio::time::timeout(Duration::from_millis(500), waiting)
            .await
            .expect("deletion must wake the long poll")
            .unwrap();
        assert_eq!(response.status, 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deletion_ends_an_inline_sse_without_waiting_for_a_heartbeat() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("sse-delete-wake");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        assert_eq!(
            handle(
                Arc::clone(&store),
                put_req("sse/deleted", "application/octet-stream"),
            )
            .await
            .status,
            201
        );
        let response = handle(
            Arc::clone(&store),
            Req {
                method: Method::Get,
                path: "sse/deleted".into(),
                query: Some("live=sse&offset=0000000000000000_0000000000000000".into()),
                headers: vec![],
                body: Bytes::new(),
            },
        )
        .await;
        let Body::Sse(mut source) = response.body else {
            panic!("expected inline SSE source")
        };
        assert!(source.next_chunk().await.is_some(), "initial control event");
        let waiting = tokio::spawn(async move { source.next_chunk().await });
        tokio::task::yield_now().await;

        assert_eq!(
            handle(
                Arc::clone(&store),
                Req {
                    method: Method::Delete,
                    path: "sse/deleted".into(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            204
        );
        let next = tokio::time::timeout(Duration::from_millis(500), waiting)
            .await
            .expect("deletion must wake the SSE source")
            .unwrap();
        assert!(next.is_none(), "a deleted stream terminates its SSE feed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lazy_expiry_fence_wakes_a_caught_up_long_poll_before_paced_retirement() {
        const CHILD: &str = "DS_TEST_EXPIRY_LONG_POLL_WAKE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "handlers::memory_mode_tests::lazy_expiry_fence_wakes_a_caught_up_long_poll_before_paced_retirement",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child lazy-expiry long-poll regression failed:\nstdout:\n{}\nstderr:\n{}",
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
                let _guard = crate::handlers::test_support::DurabilityGuard::memory();
                crate::handlers::set_long_poll_timeout(50);
                let dir = tmp("lazy-expiry-long-poll-wake");
                let store =
                    Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
                let config = crate::expiry_reaper::Config {
                    delete_rate: 100_000,
                    delete_concurrency: 1,
                    ..crate::expiry_reaper::Config::default()
                };
                let reaper = crate::expiry_reaper::spawn(store.clone(), config);
                let mut put = put_req("ttl/lp-wake", "application/octet-stream");
                put.headers.push(("stream-ttl".into(), "1".into()));
                assert_eq!(handle(store.clone(), put).await.status, 201);
                let stream = store.streams.get("ttl/lp-wake").unwrap().clone();

                let waiting = tokio::spawn(handle(
                    store.clone(),
                    Req {
                        method: Method::Get,
                        path: "ttl/lp-wake".into(),
                        query: Some(
                            "live=long-poll&offset=0000000000000000_0000000000000000".into(),
                        ),
                        headers: vec![],
                        body: Bytes::new(),
                    },
                ));
                while stream.tail_tx.receiver_count() == 0 {
                    tokio::task::yield_now().await;
                }

                // Prevent the paced worker from reaching prepare's deletion
                // wake. The request-time lookup fence itself must wake the
                // already-subscribed long poll.
                let appender = stream.appender.lock().await;
                stream.shared.write().unwrap().last_access =
                    SystemTime::now() - Duration::from_secs(2);
                assert_eq!(
                    handle(
                        store.clone(),
                        Req {
                            method: Method::Head,
                            path: "ttl/lp-wake".into(),
                            query: None,
                            headers: vec![],
                            body: Bytes::new(),
                        },
                    )
                    .await
                    .status,
                    404
                );
                let response = tokio::time::timeout(Duration::from_millis(500), waiting)
                    .await
                    .expect("lookup fencing must wake the long poll promptly")
                    .unwrap();
                assert_eq!(response.status, 404);
                assert!(stream.file_path.exists(), "paced retirement is still held");

                drop(appender);
                reaper.shutdown().await;
                crate::handlers::set_long_poll_timeout(30_000);
                drop(stream);
                drop(store);
                let _ = std::fs::remove_dir_all(&dir);
            });
    }

    #[test]
    fn lazy_expiry_fence_ends_inline_sse_before_an_open_heartbeat() {
        const CHILD: &str = "DS_TEST_EXPIRY_SSE_WAKE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "handlers::memory_mode_tests::lazy_expiry_fence_ends_inline_sse_before_an_open_heartbeat",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child lazy-expiry SSE regression failed:\nstdout:\n{}\nstderr:\n{}",
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
                let _guard = crate::handlers::test_support::DurabilityGuard::memory();
                let dir = tmp("lazy-expiry-sse-wake");
                let store =
                    Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
                let config = crate::expiry_reaper::Config {
                    delete_rate: 100_000,
                    delete_concurrency: 1,
                    ..crate::expiry_reaper::Config::default()
                };
                let reaper = crate::expiry_reaper::spawn(store.clone(), config);
                let mut put = put_req("ttl/sse-wake", "application/octet-stream");
                put.headers.push(("stream-ttl".into(), "1".into()));
                assert_eq!(handle(store.clone(), put).await.status, 201);
                let stream = store.streams.get("ttl/sse-wake").unwrap().clone();
                let mut source = SseSource {
                    st: stream.clone(),
                    rxw: stream.tail_tx.subscribe(),
                    deleted: stream.subscribe_deleted(),
                    pos: 0,
                    start: 0,
                    deadline: Instant::now() + Duration::from_millis(50),
                    client_cursor: None,
                    encoding: sse_encoding(&stream),
                    sent_initial: false,
                    done: false,
                };
                assert!(source.next().await.is_some(), "initial control event");
                let waiting = tokio::spawn(async move { source.next().await });

                let appender = stream.appender.lock().await;
                stream.shared.write().unwrap().last_access =
                    SystemTime::now() - Duration::from_secs(2);
                assert_eq!(
                    handle(
                        store.clone(),
                        Req {
                            method: Method::Head,
                            path: "ttl/sse-wake".into(),
                            query: None,
                            headers: vec![],
                            body: Bytes::new(),
                        },
                    )
                    .await
                    .status,
                    404
                );
                let next = tokio::time::timeout(Duration::from_millis(500), waiting)
                    .await
                    .expect("lookup fencing must wake the SSE source promptly")
                    .unwrap();
                assert!(
                    next.is_none(),
                    "a fenced stream must terminate instead of emitting an open heartbeat"
                );
                assert!(stream.file_path.exists(), "paced retirement is still held");

                drop(appender);
                reaper.shutdown().await;
                drop(stream);
                drop(store);
                let _ = std::fs::remove_dir_all(&dir);
            });
    }

    #[tokio::test]
    async fn fenced_hard_stream_is_404_and_persisted_soft_tombstone_is_410() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("fenced-status");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        assert_eq!(
            handle(
                Arc::clone(&store),
                put_req("status/hard", "application/octet-stream"),
            )
            .await
            .status,
            201
        );
        let hard = store.streams.get("status/hard").unwrap().clone();
        assert_eq!(store.prepare_delete(&hard).await, PrepareRetirement::Ready);
        assert_eq!(
            handle(
                Arc::clone(&store),
                post_req("status/hard", "application/octet-stream", b"x"),
            )
            .await
            .status,
            404
        );

        assert_eq!(
            handle(
                Arc::clone(&store),
                put_req("status/parent", "application/octet-stream"),
            )
            .await
            .status,
            201
        );
        let parent = store.streams.get("status/parent").unwrap().clone();
        let child_config = StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: Some("status/parent".into()),
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        assert!(matches!(
            store
                .create("status/child", child_config, Some(parent), 0)
                .unwrap(),
            CreateResult::Created(_)
        ));
        assert_eq!(
            handle(
                Arc::clone(&store),
                Req {
                    method: Method::Delete,
                    path: "status/parent".into(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            204
        );
        assert_eq!(
            handle(
                Arc::clone(&store),
                post_req("status/parent", "application/octet-stream", b"x"),
            )
            .await
            .status,
            410
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn head_does_not_touch_ttl_but_get_touches_it_atomically() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("ttl-read-admission");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let mut put = put_req("ttl/read", "application/octet-stream");
        put.headers.push(("stream-ttl".into(), "60".into()));
        assert_eq!(handle(Arc::clone(&store), put).await.status, 201);

        let stream = store.streams.get("ttl/read").unwrap().clone();
        let before = SystemTime::now() - Duration::from_millis(500);
        stream.shared.write().unwrap().last_access = before;
        assert_eq!(
            handle(
                Arc::clone(&store),
                Req {
                    method: Method::Head,
                    path: "ttl/read".into(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            200
        );
        assert_eq!(stream.shared.read().unwrap().last_access, before);

        assert_eq!(
            handle(
                Arc::clone(&store),
                Req {
                    method: Method::Get,
                    path: "ttl/read".into(),
                    query: Some("offset=0000000000000000_0000000000000000".into()),
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            200
        );
        assert!(stream.shared.read().unwrap().last_access > before);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn expired_put_retires_the_old_incarnation_before_recreating_once() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("expired-put-retry");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let expiring_put = || {
            let mut put = put_req("ttl/recreate", "application/octet-stream");
            put.headers.push(("stream-ttl".into(), "1".into()));
            put
        };
        assert_eq!(handle(Arc::clone(&store), expiring_put()).await.status, 201);
        let old = store.streams.get("ttl/recreate").unwrap().clone();
        old.shared.write().unwrap().last_access = SystemTime::now() - Duration::from_secs(2);

        assert_eq!(handle(Arc::clone(&store), expiring_put()).await.status, 201);
        let replacement = store.streams.get("ttl/recreate").unwrap().clone();
        assert_ne!(replacement.id, old.id);
        assert!(!old.file_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_put_joins_an_exact_retirement_already_queued_by_get() {
        const CHILD: &str = "DS_TEST_EXPIRED_PUT_JOIN_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // The process coordinator is intentionally process-global. Run the
            // scenario in a child test process so this regression cannot poison
            // the coordinator-free unit tests that exercise the direct fallback.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "handlers::memory_mode_tests::expired_put_joins_an_exact_retirement_already_queued_by_get",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child coordinator regression failed:\nstdout:\n{}\nstderr:\n{}",
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
                let _guard = crate::handlers::test_support::DurabilityGuard::memory();
                let dir = tmp("expired-put-join-queued");
                let store =
                    Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
                let config = crate::expiry_reaper::Config {
                    delete_rate: 100_000,
                    delete_concurrency: 1,
                    ..crate::expiry_reaper::Config::default()
                };
                let reaper = crate::expiry_reaper::spawn(store.clone(), config);
                let expiring_put = || {
                    let mut put = put_req("ttl/join", "application/octet-stream");
                    put.headers.push(("stream-ttl".into(), "1".into()));
                    put
                };
                assert_eq!(handle(store.clone(), expiring_put()).await.status, 201);
                let old = store.streams.get("ttl/join").unwrap().clone();
                old.shared.write().unwrap().last_access =
                    SystemTime::now() - Duration::from_secs(2);

                // Hold retirement before its first physical step. GET fences
                // and queues this exact incarnation; the recreate PUT must join
                // that work instead of treating AlreadyQueued as a fresh 503.
                let appender = old.appender.lock().await;
                assert_eq!(
                    handle(
                        store.clone(),
                        Req {
                            method: Method::Get,
                            path: "ttl/join".into(),
                            query: Some("offset=0000000000000000_0000000000000000".into()),
                            headers: vec![],
                            body: Bytes::new(),
                        },
                    )
                    .await
                    .status,
                    404
                );
                let mut recreate = tokio::spawn(handle(store.clone(), expiring_put()));
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), &mut recreate)
                        .await
                        .is_err(),
                    "recreate must wait for the exact queued retirement"
                );

                drop(appender);
                let response = tokio::time::timeout(Duration::from_secs(3), recreate)
                    .await
                    .expect("queued retirement and recreate timed out")
                    .unwrap();
                assert_eq!(response.status, 201);
                let replacement = store.streams.get("ttl/join").unwrap().clone();
                assert_ne!(replacement.id, old.id);
                assert!(!old.file_path.exists());

                reaper.shutdown().await;
                drop(replacement);
                drop(old);
                drop(store);
                let _ = std::fs::remove_dir_all(&dir);
            });
    }

    #[tokio::test]
    async fn request_discovered_expiry_retires_before_returning_not_found() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("lazy-expiry-retirement");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        for (name, method) in [
            ("get", Method::Get),
            ("head", Method::Head),
            ("post", Method::Post),
        ] {
            let path = format!("lazy/{name}");
            let mut put = put_req(&path, "application/octet-stream");
            put.headers.push(("stream-ttl".into(), "1".into()));
            assert_eq!(handle(Arc::clone(&store), put).await.status, 201);
            let old = store.streams.get(&path).unwrap().clone();
            old.shared.write().unwrap().last_access = SystemTime::now() - Duration::from_secs(2);
            let request = match method {
                Method::Get => Req {
                    method,
                    path: path.clone(),
                    query: Some("offset=0000000000000000_0000000000000000".into()),
                    headers: vec![],
                    body: Bytes::new(),
                },
                Method::Head => Req {
                    method,
                    path: path.clone(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
                Method::Post => post_req(&path, "application/octet-stream", b"x"),
                _ => unreachable!(),
            };
            assert_eq!(handle(Arc::clone(&store), request).await.status, 404);
            assert!(
                !old.file_path.exists(),
                "{name} must finish lazy retirement"
            );
        }

        let source_path = "lazy/fork-source";
        let mut source_put = put_req(source_path, "application/octet-stream");
        source_put.headers.push(("stream-ttl".into(), "1".into()));
        assert_eq!(handle(Arc::clone(&store), source_put).await.status, 201);
        let source = store.streams.get(source_path).unwrap().clone();
        source.shared.write().unwrap().last_access = SystemTime::now() - Duration::from_secs(2);
        let fork = Req {
            method: Method::Put,
            path: "lazy/fork-child".into(),
            query: None,
            headers: vec![
                ("content-type".into(), "application/octet-stream".into()),
                ("stream-forked-from".into(), source_path.into()),
            ],
            body: Bytes::new(),
        };
        assert_eq!(handle(Arc::clone(&store), fork).await.status, 404);
        assert!(!source.file_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_fallback_retires_a_zero_reference_fork_parent_cascade() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("fallback-fork-cascade");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        assert_eq!(
            handle(
                store.clone(),
                put_req("cascade/parent", "application/octet-stream")
            )
            .await
            .status,
            201
        );
        assert_eq!(
            handle(
                store.clone(),
                Req {
                    method: Method::Put,
                    path: "cascade/child".into(),
                    query: None,
                    headers: vec![
                        ("content-type".into(), "application/octet-stream".into()),
                        ("stream-forked-from".into(), "cascade/parent".into()),
                        ("stream-fork-offset".into(), "now".into()),
                    ],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            201
        );
        let parent = store.streams.get("cascade/parent").unwrap().clone();
        let child = store.streams.get("cascade/child").unwrap().clone();

        for path in ["cascade/parent", "cascade/child"] {
            assert_eq!(
                handle(
                    store.clone(),
                    Req {
                        method: Method::Delete,
                        path: path.into(),
                        query: None,
                        headers: vec![],
                        body: Bytes::new(),
                    },
                )
                .await
                .status,
                204
            );
        }

        assert!(!child.file_path.exists());
        assert!(
            !parent.file_path.exists(),
            "the fallback must finish the newly eligible parent continuation"
        );
        assert!(store.streams.get("cascade/parent").is_none());
        assert!(store.streams.get("cascade/child").is_none());

        drop(parent);
        drop(child);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fork_creation_does_not_fail_for_ordinary_source_appender_contention() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("fork-source-busy");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        assert_eq!(
            handle(
                store.clone(),
                put_req("fork/source", "application/octet-stream")
            )
            .await
            .status,
            201
        );
        let source = store.streams.get("fork/source").unwrap().clone();
        let source_appender = source.appender.lock().await;

        let response = handle(
            store.clone(),
            Req {
                method: Method::Put,
                path: "fork/child".into(),
                query: None,
                headers: vec![
                    ("stream-forked-from".into(), "fork/source".into()),
                    ("stream-fork-offset".into(), "now".into()),
                ],
                body: Bytes::new(),
            },
        )
        .await;
        assert_eq!(response.status, 201);
        let child = store.streams.get("fork/child").unwrap().clone();
        assert_eq!(
            child.parent.as_ref().map(|parent| parent.id),
            Some(source.id)
        );

        drop(source_appender);
        drop(child);
        drop(source);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expiry_fence_prevents_append_from_refreshing_last_access() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("append-expiry-fence");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let mut put = put_req("ttl/append-race", "application/octet-stream");
        put.headers.push(("stream-ttl".into(), "1".into()));
        assert_eq!(handle(store.clone(), put).await.status, 201);
        let stream = store.streams.get("ttl/append-race").unwrap().clone();
        let hook = crate::handlers::test_support::install_append_hook(
            crate::handlers::test_support::AppendHookPoint::AfterAdmission,
        );
        let append = tokio::spawn(handle(
            store.clone(),
            post_req("ttl/append-race", "application/octet-stream", b"x"),
        ));
        hook.reached().await;

        stream.shared.write().unwrap().last_access = SystemTime::now() - Duration::from_secs(2);
        let fence_now = SystemTime::now();
        let candidate = match store.lookup_at("ttl/append-race", fence_now, false) {
            StreamLookup::Expired(candidate) => candidate,
            _ => panic!("the request-time lookup must win the expiry fence"),
        };
        hook.release();
        assert_eq!(append.await.unwrap().status, 404);
        assert!(
            stream.is_expired_at(SystemTime::now()),
            "a fenced append must not renew last_access"
        );
        enqueue_expired_before_not_found(&store, &candidate, fence_now).await;
        assert!(
            !stream.file_path.exists(),
            "the fenced candidate must remain reapable"
        );

        drop(hook);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_fence_winning_before_tail_publication_keeps_tail_hidden() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("post-publish-fence");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        assert_eq!(
            handle(
                store.clone(),
                put_req("publish/post", "application/octet-stream")
            )
            .await
            .status,
            201
        );
        let stream = store.streams.get("publish/post").unwrap().clone();
        let hook = crate::handlers::test_support::install_append_hook(
            crate::handlers::test_support::AppendHookPoint::BeforeTailPublication,
        );
        let append = tokio::spawn(handle(
            store.clone(),
            post_req("publish/post", "application/octet-stream", b"x"),
        ));
        hook.reached().await;
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        hook.release();

        assert_eq!(append.await.unwrap().status, 404);
        assert_eq!(stream.tail().bytes, 0);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(hook);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_put_fence_winning_before_tail_publication_keeps_tail_hidden() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("put-publish-fence");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let hook = crate::handlers::test_support::install_append_hook(
            crate::handlers::test_support::AppendHookPoint::BeforeTailPublication,
        );
        let create = tokio::spawn(handle(
            store.clone(),
            Req {
                method: Method::Put,
                path: "publish/put".into(),
                query: None,
                headers: vec![("content-type".into(), "application/octet-stream".into())],
                body: Bytes::from_static(b"x"),
            },
        ));
        hook.reached().await;
        let stream = store.streams.get("publish/put").unwrap().clone();
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        hook.release();

        assert_eq!(create.await.unwrap().status, 404);
        assert_eq!(stream.tail().bytes, 0);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(hook);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_fence_winning_after_meta_keeps_eof_hidden() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("close-publish-fence");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        assert_eq!(
            handle(
                store.clone(),
                put_req("publish/close", "application/octet-stream")
            )
            .await
            .status,
            201
        );
        let stream = store.streams.get("publish/close").unwrap().clone();
        let hook = crate::handlers::test_support::install_append_hook(
            crate::handlers::test_support::AppendHookPoint::BeforeClosePublication,
        );
        let close = tokio::spawn(handle(
            store.clone(),
            Req {
                method: Method::Post,
                path: "publish/close".into(),
                query: None,
                headers: vec![("stream-closed".into(), "true".into())],
                body: Bytes::new(),
            },
        ));
        hook.reached().await;
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        hook.release();

        assert_eq!(close.await.unwrap().status, 404);
        assert!(!stream.tail().closed);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(hook);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_close_fence_before_atomic_publication_keeps_bytes_and_eof_hidden() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("body-close-publish-fence");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        assert_eq!(
            handle(
                store.clone(),
                put_req("publish/body-close", "application/octet-stream")
            )
            .await
            .status,
            201
        );
        let stream = store.streams.get("publish/body-close").unwrap().clone();
        let hook = crate::handlers::test_support::install_append_hook(
            crate::handlers::test_support::AppendHookPoint::BeforeClosePublication,
        );
        let append = tokio::spawn(handle(
            store.clone(),
            Req {
                method: Method::Post,
                path: "publish/body-close".into(),
                query: None,
                headers: vec![
                    ("content-type".into(), "application/octet-stream".into()),
                    ("stream-closed".into(), "true".into()),
                ],
                body: Bytes::from_static(b"x"),
            },
        ));
        hook.reached().await;
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        hook.release();

        assert_eq!(append.await.unwrap().status, 404);
        assert_eq!(stream.tail().bytes, 0);
        assert!(!stream.tail().closed);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(hook);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_publication_winner_is_acked_if_delete_fences_next() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("post-publication-wins");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        assert_eq!(
            handle(
                store.clone(),
                put_req("publish/post-winner", "application/octet-stream")
            )
            .await
            .status,
            201
        );
        let stream = store.streams.get("publish/post-winner").unwrap().clone();
        let hook = crate::handlers::test_support::install_append_hook(
            crate::handlers::test_support::AppendHookPoint::AfterPublication,
        );
        let append = tokio::spawn(handle(
            store.clone(),
            post_req("publish/post-winner", "application/octet-stream", b"x"),
        ));
        hook.reached().await;
        assert_eq!(stream.tail().bytes, 1);
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        hook.release();

        assert_eq!(append.await.unwrap().status, 204);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(hook);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_put_publication_winner_is_acked_if_delete_fences_next() {
        let _guard = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp("put-publication-wins");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let hook = crate::handlers::test_support::install_append_hook(
            crate::handlers::test_support::AppendHookPoint::AfterPublication,
        );
        let create = tokio::spawn(handle(
            store.clone(),
            Req {
                method: Method::Put,
                path: "publish/put-winner".into(),
                query: None,
                headers: vec![("content-type".into(), "application/octet-stream".into())],
                body: Bytes::from_static(b"x"),
            },
        ));
        hook.reached().await;
        let stream = store.streams.get("publish/put-winner").unwrap().clone();
        assert_eq!(stream.tail().bytes, 1);
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        hook.release();

        assert_eq!(create.await.unwrap().status, 201);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(hook);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod chunk_cap_tests {
    //! Read responses are bounded by the server-defined maximum chunk size
    //! (PROTOCOL.md §5.6): a capped page omits `Stream-Up-To-Date`, reports the
    //! aligned end as `Stream-Next-Offset`, and leaves `Stream-Closed` to the
    //! page that reaches the tail.
    use super::*;
    use crate::api::{Method, Req};
    use crate::store::Store;
    use crate::tier::TierConfig;
    use bytes::Bytes;

    fn tmp(tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let p = std::env::temp_dir().join(format!(
            "ds-chunk-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn put_req(path: &str, content_type: &str) -> Req {
        Req {
            method: Method::Put,
            path: path.to_string(),
            query: None,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: Bytes::new(),
        }
    }

    fn post_req(path: &str, content_type: &str, body: &[u8]) -> Req {
        Req {
            method: Method::Post,
            path: path.to_string(),
            query: None,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: Bytes::copy_from_slice(body),
        }
    }

    fn close_req(path: &str) -> Req {
        Req {
            method: Method::Post,
            path: path.to_string(),
            query: None,
            headers: vec![("stream-closed".to_string(), "true".to_string())],
            body: Bytes::new(),
        }
    }

    fn get_req(path: &str, offset: Option<u64>) -> Req {
        Req {
            method: Method::Get,
            path: path.to_string(),
            query: offset.map(|o| format!("offset={}", format_offset(o))),
            headers: vec![],
            body: Bytes::new(),
        }
    }

    fn header<'a>(resp: &'a Resp, name: &str) -> Option<&'a str> {
        resp.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    fn next_offset(resp: &Resp) -> u64 {
        header(resp, H_NEXT_OFFSET)
            .expect("every read reports Stream-Next-Offset")
            .rsplit('_')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    fn up_to_date(resp: &Resp) -> bool {
        header(resp, H_UP_TO_DATE) == Some("true")
    }

    async fn body_bytes(body: Body) -> Vec<u8> {
        match body {
            Body::Empty => Vec::new(),
            Body::Full(b) => b.to_vec(),
            Body::FileRange {
                segments,
                prefix,
                suffix,
                ..
            } => {
                let mut out = prefix.to_vec();
                out.extend_from_slice(&crate::store::materialize_segments(&segments));
                out.extend_from_slice(suffix);
                out
            }
            // Cold/mixed ranges stream their framed slices over a channel.
            Body::Channel(stream) => {
                let mut rx = stream.rx;
                let mut out = Vec::new();
                while let Some(chunk) = rx.recv().await {
                    out.extend_from_slice(&chunk);
                }
                assert!(
                    !stream.failed.load(std::sync::atomic::Ordering::Acquire),
                    "the streamed body must not abort"
                );
                out
            }
            _ => panic!("unexpected streaming body for a catch-up read"),
        }
    }

    async fn create(store: &Arc<Store>, path: &str, content_type: &str) {
        let resp = handle(Arc::clone(store), put_req(path, content_type)).await;
        assert_eq!(resp.status, 201, "create {path}");
    }

    async fn append(store: &Arc<Store>, path: &str, content_type: &str, body: &[u8]) {
        let resp = handle(Arc::clone(store), post_req(path, content_type, body)).await;
        assert!(
            (200..300).contains(&resp.status),
            "append to {path}: {}",
            resp.status
        );
    }

    async fn read(store: &Arc<Store>, path: &str, offset: Option<u64>) -> Resp {
        handle(Arc::clone(store), get_req(path, offset)).await
    }

    fn json_item(index: usize, pad: usize) -> String {
        format!(r#"{{"i":{index},"pad":"{}"}}"#, "a".repeat(pad))
    }

    /// A JSON stream larger than the cap is paged: each page is a valid JSON
    /// array cut on a value boundary, carries no `Stream-Up-To-Date`, and the
    /// follow-up read from its `Stream-Next-Offset` returns the rest.
    #[tokio::test]
    async fn json_pages_are_valid_arrays_and_resume_from_next_offset() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(512);
        let dir = tmp("json-pages");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/json", "application/json").await;
        for i in 0..40 {
            append(
                &store,
                "c/json",
                "application/json",
                json_item(i, 60).as_bytes(),
            )
            .await;
        }
        let tail = store.streams.get("c/json").unwrap().tail().bytes;

        let first = read(&store, "c/json", None).await;
        assert_eq!(first.status, 200);
        assert!(
            !up_to_date(&first),
            "a chunk-capped page must not claim Stream-Up-To-Date (§5.6)"
        );
        let cut = next_offset(&first);
        assert!(
            cut > 0 && cut < tail,
            "partial next offset: {cut} of {tail}"
        );
        assert!(cut <= 512, "the page must respect the cap, got {cut} bytes");

        let mut seen: Vec<serde_json::Value> = Vec::new();
        let mut offset = None;
        let mut pages = 0;
        loop {
            let resp = read(&store, "c/json", offset).await;
            assert_eq!(resp.status, 200);
            pages += 1;
            assert!(pages < 100, "paging must terminate");
            let done = up_to_date(&resp);
            let at = next_offset(&resp);
            let body = body_bytes(resp.body).await;
            let parsed: Vec<serde_json::Value> = serde_json::from_slice(&body)
                .unwrap_or_else(|e| panic!("page must be a valid JSON array: {e}"));
            seen.extend(parsed);
            if done {
                assert_eq!(at, tail, "the final page reports the tail");
                break;
            }
            offset = Some(at);
        }
        assert!(pages > 1, "the stream must have been split into pages");
        assert_eq!(seen.len(), 40, "every appended value is delivered once");
        for (i, value) in seen.iter().enumerate() {
            assert_eq!(
                value["i"],
                serde_json::json!(i as i64),
                "values stay ordered"
            );
        }
    }

    /// A byte stream may be cut at any byte: the page is exactly the cap.
    #[tokio::test]
    async fn byte_stream_is_cut_at_the_cap() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(256);
        let dir = tmp("bytes-cut");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/bytes", "application/octet-stream").await;
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        append(&store, "c/bytes", "application/octet-stream", &payload).await;

        let first = read(&store, "c/bytes", None).await;
        assert_eq!(next_offset(&first), 256);
        assert!(!up_to_date(&first));
        let head = body_bytes(first.body).await;
        assert_eq!(head, payload[..256], "the page is the first cap bytes");

        let mut all = head;
        let mut offset = 256;
        loop {
            let resp = read(&store, "c/bytes", Some(offset)).await;
            let done = up_to_date(&resp);
            offset = next_offset(&resp);
            all.extend_from_slice(&body_bytes(resp.body).await);
            if done {
                break;
            }
        }
        assert_eq!(all, payload, "paging reassembles the stream exactly");
    }

    /// `--max-chunk-bytes 0` restores the uncapped single-response behaviour.
    #[tokio::test]
    async fn cap_zero_is_unlimited() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(0);
        let dir = tmp("cap-zero");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/unlimited", "application/octet-stream").await;
        let payload = vec![b'x'; 100_000];
        append(&store, "c/unlimited", "application/octet-stream", &payload).await;

        let resp = read(&store, "c/unlimited", None).await;
        assert!(up_to_date(&resp), "an uncapped read is up to date");
        assert_eq!(next_offset(&resp), 100_000);
        assert_eq!(body_bytes(resp.body).await.len(), 100_000);
    }

    /// A single JSON value larger than the cap has no in-cap value boundary. The
    /// page must never come back empty: the oversize value is served whole.
    #[tokio::test]
    async fn oversize_json_value_is_served_whole() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(64);
        let dir = tmp("oversize-json");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/big", "application/json").await;
        let big = json_item(0, 4000);
        append(&store, "c/big", "application/json", big.as_bytes()).await;
        append(
            &store,
            "c/big",
            "application/json",
            json_item(1, 8).as_bytes(),
        )
        .await;

        let resp = read(&store, "c/big", None).await;
        assert_eq!(resp.status, 200);
        assert!(!up_to_date(&resp), "more values remain after the big one");
        assert_eq!(
            next_offset(&resp),
            big.len() as u64 + 1,
            "the cut lands just past the oversize value's separator"
        );
        let parsed: Vec<serde_json::Value> =
            serde_json::from_slice(&body_bytes(resp.body).await).unwrap();
        assert_eq!(parsed.len(), 1, "exactly the oversize value is returned");
        assert_eq!(parsed[0]["i"], serde_json::json!(0));
    }

    /// A closed stream is closed *to the reader* only once the last page is
    /// delivered: intermediate pages must not claim `Stream-Closed` (§5.6).
    #[tokio::test]
    async fn closed_is_reported_only_on_the_final_page() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(128);
        let dir = tmp("closed-pages");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/closed", "application/octet-stream").await;
        append(
            &store,
            "c/closed",
            "application/octet-stream",
            &vec![b'y'; 500],
        )
        .await;
        assert!((200..300).contains(
            &handle(Arc::clone(&store), close_req("c/closed"))
                .await
                .status
        ));

        let first = read(&store, "c/closed", None).await;
        assert!(
            header(&first, H_CLOSED).is_none(),
            "a partial page of a closed stream must not report Stream-Closed"
        );
        assert!(!up_to_date(&first));

        let mut offset = next_offset(&first);
        let mut last = first;
        while !up_to_date(&last) {
            last = read(&store, "c/closed", Some(offset)).await;
            offset = next_offset(&last);
        }
        assert_eq!(offset, 500);
        assert_eq!(
            header(&last, H_CLOSED),
            Some("true"),
            "the page that reaches the tail reports closure"
        );
    }

    /// The ETag covers the range actually returned, and a conditional request
    /// for a capped page answers 304 with the same partial-page headers.
    #[tokio::test]
    async fn conditional_request_matches_the_partial_page() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(128);
        let dir = tmp("partial-etag");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/etag", "application/octet-stream").await;
        append(
            &store,
            "c/etag",
            "application/octet-stream",
            &vec![b'z'; 400],
        )
        .await;

        let first = read(&store, "c/etag", None).await;
        let etag = header(&first, "etag")
            .expect("a range read is cacheable")
            .to_string();
        let mut conditional = get_req("c/etag", None);
        conditional
            .headers
            .push(("if-none-match".into(), etag.clone()));
        let resp = handle(Arc::clone(&store), conditional).await;
        assert_eq!(resp.status, 304);
        assert_eq!(next_offset(&resp), 128);
        assert!(
            !up_to_date(&resp),
            "the 304 for a partial page must not claim up-to-date either"
        );
    }

    fn fork_req(path: &str, source: &str, offset: u64, sub_offset: u64) -> Req {
        Req {
            method: Method::Put,
            path: path.to_string(),
            query: None,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("stream-forked-from".into(), source.to_string()),
                ("stream-fork-offset".into(), format_offset(offset)),
                ("stream-fork-sub-offset".into(), sub_offset.to_string()),
            ],
            body: Bytes::new(),
        }
    }

    /// Read a whole stream by paging, asserting every page is a valid JSON array
    /// and that only the final page claims up-to-date.
    async fn drain_json(store: &Arc<Store>, path: &str) -> Vec<serde_json::Value> {
        let mut values = Vec::new();
        let mut offset = None;
        for _ in 0..200 {
            let resp = read(store, path, offset).await;
            assert_eq!(resp.status, 200, "page of {path}");
            let done = up_to_date(&resp);
            let at = next_offset(&resp);
            let page: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes(resp.body).await)
                .unwrap_or_else(|e| panic!("page of {path} must be a valid JSON array: {e}"));
            values.extend(page);
            offset = Some(at);
            if done {
                return values;
            }
        }
        panic!("paging {path} did not terminate")
    }

    /// A `Stream-Fork-Sub-Offset` counts MESSAGES, so it must be resolved with the
    /// top-level value scanner. Counting raw commas puts the fork point inside a
    /// value (here, inside `[1,2]`), which makes every later read of the fork
    /// malformed JSON and leaves the chunk cap's scanner with no boundary to find.
    #[tokio::test]
    async fn fork_sub_offset_counts_top_level_values_not_raw_commas() {
        let _durability = test_support::DurabilityGuard::memory();
        let dir = tmp("fork-sub-offset");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "f/parent", "application/json").await;
        let first = r#"{"a":[1,2],"b":"x,y"}"#;
        append(&store, "f/parent", "application/json", first.as_bytes()).await;
        append(&store, "f/parent", "application/json", br#"{"c":3}"#).await;

        let resp = handle(Arc::clone(&store), fork_req("f/child", "f/parent", 0, 1)).await;
        assert_eq!(resp.status, 201, "fork create");
        let child = store.streams.get("f/child").unwrap().clone();
        assert_eq!(
            child.base_offset,
            first.len() as u64 + 1,
            "the fork point must be one whole value in, not one raw comma in"
        );

        let values = drain_json(&store, "f/child").await;
        assert_eq!(
            values,
            vec![serde_json::from_str::<serde_json::Value>(first).unwrap()]
        );
    }

    /// A fork read that crosses both the fork point and the chunk cap still pages
    /// as valid JSON: inherited parent values and the fork's own values arrive
    /// once each, in order.
    #[tokio::test]
    async fn fork_reads_page_across_the_cap() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(512);
        let dir = tmp("fork-cap");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "f/src", "application/json").await;
        for i in 0..20 {
            append(
                &store,
                "f/src",
                "application/json",
                json_item(i, 60).as_bytes(),
            )
            .await;
        }
        let resp = handle(Arc::clone(&store), fork_req("f/fork", "f/src", 0, 20)).await;
        assert_eq!(resp.status, 201, "fork create");
        for i in 20..40 {
            append(
                &store,
                "f/fork",
                "application/json",
                json_item(i, 60).as_bytes(),
            )
            .await;
        }

        let values = drain_json(&store, "f/fork").await;
        assert_eq!(
            values.len(),
            40,
            "inherited + own values, each exactly once"
        );
        for (i, value) in values.iter().enumerate() {
            assert_eq!(value["i"], serde_json::json!(i as i64));
        }
    }

    /// The cold path: with sealed/offloaded segments under the read, capped pages
    /// still cut on value boundaries and reassemble exactly.
    #[tokio::test]
    async fn cold_tier_pages_are_valid_json() {
        use crate::tier::TierKind;
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(512);
        let dir = tmp("cold-cap");
        let tier = TierConfig {
            kind: TierKind::Local,
            segment_bytes: 1024,
            local_dir: Some(dir.join("cold")),
            ..Default::default()
        };
        let store = Arc::new(Store::new_with_tier(dir.clone(), tier).unwrap());
        create(&store, "cold/json", "application/json").await;
        for i in 0..60 {
            append(
                &store,
                "cold/json",
                "application/json",
                json_item(i, 60).as_bytes(),
            )
            .await;
        }
        let st = store.streams.get("cold/json").unwrap().clone();
        store.maybe_seal(&st).await;
        assert!(
            st.tier.manifest.lock().unwrap().sealed_offset > 0,
            "the test must actually seal a cold prefix"
        );

        let values = drain_json(&store, "cold/json").await;
        assert_eq!(values.len(), 60);
        for (i, value) in values.iter().enumerate() {
            assert_eq!(value["i"], serde_json::json!(i as i64));
        }
    }

    /// A client-fabricated offset that lands inside a JSON value has no top-level
    /// boundary to cut on. The cap must fail closed rather than fall back to the
    /// whole tail — that would serve an unbounded, malformed page and mark it
    /// up-to-date.
    #[tokio::test]
    async fn mid_value_offset_fails_closed_instead_of_serving_the_tail() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(256);
        let dir = tmp("mid-value");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/strings", "application/json").await;
        // Comma-free string values: a scan starting inside one never sees a
        // top-level separator, so the range is provably not value-aligned.
        for _ in 0..8 {
            let value = format!("\"{}\"", "a".repeat(200));
            append(&store, "c/strings", "application/json", value.as_bytes()).await;
        }
        let resp = read(&store, "c/strings", Some(3)).await;
        assert_eq!(
            resp.status, 400,
            "a mid-value offset must be refused, not served as a malformed page"
        );

        // The same stream read from a server-issued offset still pages fine.
        let values = drain_json(&store, "c/strings").await;
        assert_eq!(values.len(), 8);
    }

    /// SSE catch-up is bounded by the same cap. A subscriber starting at
    /// `offset=0` on a large stream used to materialize and encode the whole
    /// backlog in one frame; it now arrives as several data/control pairs, with
    /// `upToDate` only on the last.
    #[tokio::test]
    async fn sse_catch_up_is_delivered_in_capped_frames() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(512);
        let dir = tmp("sse-cap");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "sse/json", "application/json").await;
        for i in 0..40 {
            append(
                &store,
                "sse/json",
                "application/json",
                json_item(i, 60).as_bytes(),
            )
            .await;
        }

        let resp = handle(
            Arc::clone(&store),
            Req {
                method: Method::Get,
                path: "sse/json".into(),
                query: Some(format!("live=sse&offset={}", format_offset(0))),
                headers: vec![],
                body: Bytes::new(),
            },
        )
        .await;
        let Body::Sse(mut source) = resp.body else {
            panic!("expected an inline SSE source")
        };

        let mut values: Vec<serde_json::Value> = Vec::new();
        let mut frames = 0;
        loop {
            let chunk = source
                .next_chunk()
                .await
                .expect("SSE must reach up-to-date");
            let frame = String::from_utf8(chunk.to_vec()).unwrap();
            frames += 1;
            assert!(frames < 50, "SSE catch-up must terminate");
            for line in frame.lines() {
                if let Some(payload) = line.strip_prefix("data:[") {
                    let page: Vec<serde_json::Value> =
                        serde_json::from_str(&format!("[{payload}")).expect("valid JSON array");
                    assert!(
                        payload.len() < 512 + 64,
                        "an SSE data frame must respect the cap"
                    );
                    values.extend(page);
                }
            }
            if frame.contains("\"upToDate\":true") {
                break;
            }
        }
        assert!(frames > 1, "the backlog must be split across frames");
        assert_eq!(values.len(), 40, "every value arrives exactly once");
        for (i, value) in values.iter().enumerate() {
            assert_eq!(value["i"], serde_json::json!(i as i64));
        }
    }

    /// A capped `text/*` SSE frame is encoded lossily, so the cut must not land
    /// inside a multi-byte character.
    #[tokio::test]
    async fn capped_text_sse_frames_do_not_split_utf8() {
        // 100 is not a multiple of 3, so an unaligned cut would land inside one
        // of the three-byte characters below.
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(100);
        let dir = tmp("sse-utf8");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "sse/text", "text/plain").await;
        let payload = "★".repeat(200);
        append(&store, "sse/text", "text/plain", payload.as_bytes()).await;

        let resp = handle(
            Arc::clone(&store),
            Req {
                method: Method::Get,
                path: "sse/text".into(),
                query: Some(format!("live=sse&offset={}", format_offset(0))),
                headers: vec![],
                body: Bytes::new(),
            },
        )
        .await;
        let Body::Sse(mut source) = resp.body else {
            panic!("expected an inline SSE source")
        };

        let mut text = String::new();
        let mut frames = 0;
        for _ in 0..50 {
            let chunk = source
                .next_chunk()
                .await
                .expect("SSE must reach up-to-date");
            let frame = String::from_utf8(chunk.to_vec()).unwrap();
            frames += 1;
            // One chunk carries a `data` event followed by its `control` event;
            // only the former holds stream bytes.
            let mut in_data = false;
            for line in frame.lines() {
                if let Some(kind) = line.strip_prefix("event: ") {
                    in_data = kind == "data";
                } else if in_data {
                    if let Some(data) = line.strip_prefix("data:") {
                        text.push_str(data);
                    }
                }
            }
            if frame.contains("\"upToDate\":true") {
                break;
            }
        }
        assert!(frames > 1, "the text backlog must be split across frames");
        assert!(
            !text.contains('\u{fffd}'),
            "a capped text frame must not split a UTF-8 character"
        );
        assert_eq!(text, payload, "the text stream reassembles exactly");
    }

    /// The boundary scan already materializes the page's bytes; serving the body
    /// by resolving and reading the same range again doubles the I/O of every
    /// capped JSON page (one extra range read per page on a cold tier).
    #[tokio::test]
    async fn capped_json_page_is_served_from_the_scanned_bytes() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(512);
        let dir = tmp("json-single-read");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/once", "application/json").await;
        for i in 0..40 {
            append(
                &store,
                "c/once",
                "application/json",
                json_item(i, 60).as_bytes(),
            )
            .await;
        }

        let resp = read(&store, "c/once", None).await;
        assert!(!up_to_date(&resp), "the page must be capped");
        assert!(
            matches!(resp.body, Body::Full(_)),
            "a capped JSON page must be served from the bytes the boundary scan \
             already read, not resolved and read a second time"
        );
        let values: Vec<serde_json::Value> =
            serde_json::from_slice(&body_bytes(resp.body).await).unwrap();
        assert_eq!(values[0]["i"], serde_json::json!(0));
    }

    /// A value larger than the cap must be located by scanning forward once.
    /// Growing the window geometrically re-reads everything scanned so far, so a
    /// 20 KiB value at a 1 KiB cap costs ~52 KiB of reads instead of ~21 KiB.
    #[tokio::test]
    async fn oversize_json_value_is_scanned_without_rereads() {
        use std::sync::atomic::Ordering;
        let cap = 1024;
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(cap);
        let dir = tmp("no-reread");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/reread", "application/json").await;
        let big = json_item(0, 20_000);
        append(&store, "c/reread", "application/json", big.as_bytes()).await;
        for i in 1..5 {
            append(
                &store,
                "c/reread",
                "application/json",
                json_item(i, 60).as_bytes(),
            )
            .await;
        }

        BOUNDARY_SCAN_BYTES.store(0, Ordering::Relaxed);
        let resp = read(&store, "c/reread", None).await;
        let page_wire = big.len() as u64 + 1;
        assert_eq!(
            next_offset(&resp),
            page_wire,
            "the oversize value is one page"
        );
        let scanned = BOUNDARY_SCAN_BYTES.load(Ordering::Relaxed);
        assert!(
            scanned <= page_wire + cap,
            "the boundary scan must read each byte once: read {scanned} bytes for a \
             {page_wire}-byte page at a {cap}-byte cap"
        );
    }

    /// The chunk cap is a process-wide global, exactly like the durability mode,
    /// so its test guard must hold the SAME lock. With a lock of its own, a test
    /// holding only the durability guard can be running while a chunk test sets a
    /// 128-byte cap — and unrelated reads then page unexpectedly.
    #[test]
    fn the_chunk_cap_guard_shares_the_durability_lock() {
        let (tx, rx) = std::sync::mpsc::channel();
        let held = test_support::DurabilityGuard::memory();
        let worker = std::thread::spawn(move || {
            let _capped = test_support::DurabilityGuard::memory_with_max_chunk(128);
            let _ = tx.send(max_chunk_bytes());
            std::thread::sleep(Duration::from_millis(50));
        });

        let observed = rx.recv_timeout(Duration::from_millis(250));
        assert!(
            observed.is_err(),
            "the cap must not change while another test holds the durability lock; observed {observed:?}"
        );
        drop(held);
        worker.join().unwrap();
        assert_eq!(
            max_chunk_bytes(),
            DEFAULT_MAX_CHUNK_BYTES,
            "dropping the guard restores the default cap"
        );
    }

    /// A long-poll that returns a backlog is a read like any other: the same cap
    /// applies, so one wake cannot deliver a whole stream.
    #[tokio::test]
    async fn long_poll_backlog_is_capped() {
        let _durability = test_support::DurabilityGuard::memory_with_max_chunk(256);
        let dir = tmp("long-poll-cap");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        create(&store, "c/lp", "application/octet-stream").await;
        append(&store, "c/lp", "application/octet-stream", &vec![b'q'; 900]).await;

        let resp = handle(
            Arc::clone(&store),
            Req {
                method: Method::Get,
                path: "c/lp".into(),
                query: Some(format!("live=long-poll&offset={}", format_offset(0))),
                headers: vec![],
                body: Bytes::new(),
            },
        )
        .await;
        assert_eq!(resp.status, 200);
        assert_eq!(next_offset(&resp), 256);
        assert!(!up_to_date(&resp), "a capped long-poll page is partial");
        assert_eq!(body_bytes(resp.body).await.len(), 256);
    }
}
