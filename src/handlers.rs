// HTTP protocol handlers for Durable Streams — engine-agnostic (see api.rs).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::{BufMut, Bytes, BytesMut};
use serde_json::value::RawValue;
use tokio::sync::{mpsc, watch};
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
    use super::{set_durability, DurabilityMode};
    use std::sync::{Mutex, MutexGuard};

    static MODE_LOCK: Mutex<()> = Mutex::new(());

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
    }

    impl Drop for DurabilityGuard {
        fn drop(&mut self) {
            set_durability(DurabilityMode::Wal);
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
    } else if path == "/_admin/expiry" {
        "/_admin/expiry"
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
                response.body = full(body);
                response
            }
            ("/_admin/inventory", Method::Get, Some(_)) => {
                inventory_response(&store, req.query.as_deref())
            }
            ("/_admin/expiry", Method::Get, Some(admin)) => {
                let mut response = Resp::new(200);
                response
                    .headers
                    .push(("content-type", "application/json".to_string()));
                response.body = full(admin.expiry_json(&store));
                response
            }
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
    let mut source_lease: Option<ForkSourceLease> = None;
    if let Some(src_path) = &forked_from {
        let src = match store.registered_stream(src_path) {
            Some(s) => s,
            None => return text_response(404, "fork source not found"),
        };
        let appender = src.appender.lock().await;
        match store.liveness_while_appender_locked(&src, SystemTime::now()) {
            AppenderLiveness::Missing => return text_response(404, "fork source not found"),
            AppenderLiveness::Gone => return text_response(409, "fork source is deleted"),
            AppenderLiveness::Expired => {
                drop(appender);
                let _ = store.retire_expiry(src).await;
                return text_response(404, "fork source not found");
            }
            AppenderLiveness::Live => {
                source_lease = ForkSourceLease::begin(&src, &appender);
                drop(appender);
                if source_lease.is_none() {
                    return text_response(404, "fork source not found");
                }
            }
        }
        #[cfg(test)]
        crate::test_cut_points::hit_async(crate::test_cut_points::CutPoint::ForkSourceLease, &src)
            .await;
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
                // Sub-offset counts messages past the anchor; each message ends with ','.
                // NOTE: this materializes the whole `[anchor, src_tail)` range to
                // scan for the Nth comma, even for a small `sub` over a huge stream
                // — O(tail) memory. Acceptable here: fork-create is a cold control
                // op, not a hot path. A bounded-window scan would remove the cost.
                let data = match read_range_bytes(&src, anchor, src_tail).await {
                    Ok(d) => d,
                    // A short/cold read must not be miscounted as a value boundary.
                    Err(_) => return text_response(503, "fork source read failed"),
                };
                let mut remaining = sub;
                let mut adv = 0u64;
                for (i, b) in data.iter().enumerate() {
                    if *b == b',' {
                        remaining -= 1;
                        if remaining == 0 {
                            adv = i as u64 + 1;
                            break;
                        }
                    }
                }
                if remaining > 0 {
                    return text_response(400, "sub-offset overshoots message count");
                }
                anchor + adv
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

    // Classify an occupied target under its appender lifecycle lock before any
    // provisional-file work. An expiry owner may make exactly one vacant-create
    // attempt after the bounded logical phase completes.
    match store.put_target_admission(&path, &config).await {
        PutTargetAdmission::Vacant => {}
        PutTargetAdmission::Compatible(st) => return existing_create_response(&st),
        PutTargetAdmission::Conflict => {
            return text_response(409, "stream exists with different configuration")
        }
        PutTargetAdmission::Retryable => return retirement_retry_after("1"),
        PutTargetAdmission::Expired(stream) => {
            // A self-fork holds this exact source's lease. Retiring it here
            // would fence and wait for the lease we still own, so leave it for
            // the next request's source-liveness path instead.
            if parent
                .as_ref()
                .is_some_and(|source| Arc::ptr_eq(source, &stream))
            {
                return retirement_retry_after("1");
            }
            match store.retire_expiry(stream).await {
                ExplicitRetirementResult::Owner(_) => {
                    match store.put_target_admission(&path, &config).await {
                        PutTargetAdmission::Vacant => {}
                        PutTargetAdmission::Compatible(st) => return existing_create_response(&st),
                        PutTargetAdmission::Conflict => {
                            return text_response(409, "stream exists with different configuration")
                        }
                        // This PUT has already performed its one expiry retirement;
                        // do not adopt another incumbent or loop on a moving target.
                        PutTargetAdmission::Expired(_) | PutTargetAdmission::Retryable => {
                            return retirement_retry_after("1")
                        }
                    }
                }
                // A retained fork tombstone is stable but cannot be re-created.
                ExplicitRetirementResult::Gone => {
                    return text_response(409, "stream exists with different configuration")
                }
                ExplicitRetirementResult::Existing(_)
                | ExplicitRetirementResult::Missing
                | ExplicitRetirementResult::Stale
                | ExplicitRetirementResult::Rejected(_)
                | ExplicitRetirementResult::Unavailable
                | ExplicitRetirementResult::Renewed(_)
                | ExplicitRetirementResult::Cancelled(_) => return retirement_retry_after("1"),
            }
        }
    }

    // Run the one vacant create attempt on the blocking pool: it opens the data
    // file and does a durable
    // (fsync) `.meta` write, which would otherwise block an async worker for the
    // whole fsync. Under concurrent stream creation that throttles creates to
    // ~(worker_count / fsync_latency) and times them out (the "stream creation
    // doesn't scale past ~200 PUTs" finding). On the blocking pool many creates
    // fsync concurrently and the async workers stay free to dispatch.
    let result = {
        let store = store.clone();
        let create_path = path.clone();
        let create_config = config.clone();
        match tokio::task::spawn_blocking(move || {
            store.create(&create_path, create_config, parent, base_offset)
        })
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return text_response(500, &e.to_string()),
            Err(_) => return text_response(500, "create task failed"),
        }
    };
    // The source lease spans parent selection, target admission, and the full
    // blocking create transaction. A Created result has durably incremented
    // the parent refcount; every other result has completed its rollback.
    drop(source_lease);
    match result {
        // An entry may have won the final DashMap race after the preflight.
        // Classify that exact winner under its appender lock; never write this
        // request's initial body into a winner it did not create.
        CreateResult::Conflict => classify_occupied_create_race(&store, &path, None, &config).await,
        CreateResult::Exists(existing) => {
            // Classify this exact winner, so a concurrent retirement cannot
            // make an identity-less occupied race look vacant.
            classify_occupied_create_race(&store, &path, Some(existing), &config).await
        }
        CreateResult::Created(st) => {
            let notify_subscription = wire.is_some();
            let mut _inflight_append = None;
            if let Some(wire) = wire {
                let lock_t0 = crate::telemetry::Timer::start();
                let mut ap = st.appender.lock().await;
                crate::telemetry::record_append_lock_wait(lock_t0.elapsed_secs());
                _inflight_append = Some(match InflightAppendGuard::begin(&st, &ap) {
                    Some(guard) => guard,
                    None => return text_response(404, "stream not found"),
                });
                let pre_written = ap.written;
                let pre_last_access = st.shared.read().unwrap().last_access;
                let new_tail = match write_wire(&st, &mut ap, &wire) {
                    Ok(t) => t,
                    Err(_) => return text_response(500, "write failed"),
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
                            sh.last_access = pre_last_access;
                        }
                        return text_response(500, "wal stage failed");
                    }
                };
                drop(ap);
                #[cfg(test)]
                crate::test_cut_points::hit_async(
                    crate::test_cut_points::CutPoint::AppendAfterAppenderDropBeforeWalWait,
                    &st,
                )
                .await;
                if let Some(lsn) = staged_lsn {
                    wait_durable_lsn(&store, &st, lsn).await;
                }
                #[cfg(test)]
                crate::test_cut_points::hit_async(
                    crate::test_cut_points::CutPoint::AppendPostDurablePreVisible,
                    &st,
                )
                .await;
                if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
                    return text_response(404, "stream not found");
                }
                // Durable now (wal) / page-cache written (memory): expose to readers.
                publish_durable_tail(&store, &st, new_tail, &wire);
            }
            if notify_subscription {
                if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
                    return text_response(404, "stream not found");
                }
                store
                    .subscriptions
                    .clone()
                    .on_stream_append(store.clone(), &st.path)
                    .await;
            }
            if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
                return text_response(404, "stream not found");
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
            b.body(empty())
        }
    }
}

fn existing_create_response(st: &StreamState) -> Resp {
    let t = st.tail();
    let mut response = ResponseBuilder::new(200)
        .h("content-type", st.config.content_type.clone())
        .h(H_NEXT_OFFSET, format_offset(t.bytes));
    if t.closed {
        response = response.hs(H_CLOSED, "true");
    }
    response.body(empty())
}

async fn classify_occupied_create_race(
    store: &Arc<Store>,
    path: &str,
    winner: Option<Arc<StreamState>>,
    config: &StreamConfig,
) -> Resp {
    let admission = match winner {
        Some(winner) => store.put_target_admission_for(winner, config).await,
        None => store.put_target_admission(path, config).await,
    };
    match admission {
        PutTargetAdmission::Compatible(st) => existing_create_response(&st),
        PutTargetAdmission::Conflict => {
            text_response(409, "stream exists with different configuration")
        }
        PutTargetAdmission::Vacant
        | PutTargetAdmission::Expired(_)
        | PutTargetAdmission::Retryable => retirement_retry_after("1"),
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
fn write_wire(st: &StreamState, ap: &mut Appender, wire: &Bytes) -> std::io::Result<u64> {
    use std::io::Write;
    if let Err(e) = (&*ap.file).write_all(wire) {
        // A partial write (ENOSPC mid-slice) leaves garbage bytes in the file
        // PAST `ap.written` while the logical offsets don't advance — every
        // later append would land after the garbage (O_APPEND) with a logical
        // offset that assumes it landed at `ap.written`: silent, permanent
        // offset desync for all subsequent data. Truncate back to the exact
        // pre-write length so physical == logical again.
        let _ = ap.file.set_len(ap.written);
        return Err(e);
    }
    ap.written += wire.len() as u64;
    let tail = {
        let mut s = st.shared.write().unwrap();
        let tail = s.file_base + ap.written;
        s.tail = tail;
        s.last_access = SystemTime::now();
        tail
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
fn publish_durable_tail(store: &Store, st: &StreamState, tail: u64, wire: &Bytes) {
    let closed;
    {
        let mut s = st.shared.write().unwrap();
        if tail <= s.durable_tail {
            // A concurrent appender already published an equal/greater durable
            // frontier — nothing to expose, and re-firing would regress the watch.
            return;
        }
        s.durable_tail = tail;
        closed = s.closed_durable;
    }
    // Publish the resident chunk BEFORE waking subscribers, so a long-poll/SSE
    // reader woken by the tail update reliably hits the cache (one shared copy)
    // instead of racing ahead and falling back to a file read. The chunk spans
    // [tail - wire.len(), tail).
    st.set_last_chunk(tail - wire.len() as u64, wire.clone());
    st.tail_tx.send_replace(Tail {
        bytes: tail,
        closed,
    });
    // Inventory observes the already-published durable tail. This deliberately
    // adds no fsync to the append hot path; a generation-bound page detects
    // concurrent change and backup quiescence supplies a stable window.
    store.publish_inventory_tail(st);
    // Wake any reactor-served subscribers of this stream (no-op when none).
    #[cfg(target_os = "linux")]
    crate::sse_reactor::wake_stream(st);
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
    let st = match store.registered_stream(&path) {
        Some(s) => s,
        None => return (text_response(404, "stream not found"), Conflict, false),
    };
    let is_json = st.is_json;
    macro_rules! ret {
        ($resp:expr, $oc:expr) => {
            return ($resp, $oc, is_json)
        };
    }
    // Serialize per stream: producer validation + write + state update under one
    // lock. Time the wait separately — lock contention is a key bottleneck.
    let lock_t0 = crate::telemetry::Timer::start();
    let srv_lock_t0 = std::time::Instant::now();
    let mut ap = st.appender.lock().await;
    crate::telemetry::record_append_lock_wait(lock_t0.elapsed_secs());
    crate::srvstats::record_applock_wait(srv_lock_t0.elapsed());

    match store.liveness_while_appender_locked(&st, SystemTime::now()) {
        AppenderLiveness::Live => {}
        AppenderLiveness::Gone => ret!(gone(), Conflict),
        AppenderLiveness::Missing => ret!(text_response(404, "stream not found"), Conflict),
        AppenderLiveness::Expired => {
            drop(ap);
            let _ = store.retire_expiry(st).await;
            ret!(text_response(404, "stream not found"), Conflict);
        }
    }

    // Keep the accepted liveness guard through durability and the complete
    // response fence, including duplicate and close-only branches below.
    let _inflight_append = match InflightAppendGuard::begin(&st, &ap) {
        Some(guard) => guard,
        None => ret!(text_response(404, "stream not found"), Conflict),
    };

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
            Some(ct) if media_type(ct) != media_type(&st.config.content_type) => {
                // Closed still takes precedence over a type mismatch, after the
                // request has won its lifecycle decision.
                let t = st.tail();
                if t.closed && !close_req {
                    ret!(closed_conflict(t.bytes), Closed);
                }
                ret!(text_response(409, "content-type mismatch"), Conflict);
            }
            Some(_) => {}
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
    let (prev_producer, prev_seq_header, prev_last_access) = {
        let sh = st.shared.read().unwrap();
        (
            producer
                .as_ref()
                .map(|p| (p.id.clone(), sh.producers.get(&p.id).cloned())),
            sh.last_seq_header.clone(),
            sh.last_access,
        )
    };
    if !wire.is_empty() {
        match write_wire(&st, &mut ap, &wire) {
            Ok(t) => new_tail = Some(t),
            Err(_) => ret!(text_response(500, "write failed"), Conflict),
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
    {
        let mut s = st.shared.write().unwrap();
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
        if let Some(seq) = seq_header {
            s.last_seq_header = Some(seq);
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
                    sh.tail = sh.file_base + pre_written;
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
                    sh.last_access = prev_last_access;
                    if close_req {
                        sh.closed = false;
                        sh.closed_by = None;
                    }
                }
                ret!(text_response(500, "wal stage failed"), Conflict)
            }
        }
    } else {
        None
    };
    drop(ap);
    #[cfg(test)]
    crate::test_cut_points::hit_async(
        crate::test_cut_points::CutPoint::AppendAfterAppenderDropBeforeWalWait,
        &st,
    )
    .await;

    // Wait for durability off the lock before exposing the bytes.
    if let Some(lsn) = staged_lsn {
        let dur_t0 = std::time::Instant::now();
        wait_durable_lsn(&store, &st, lsn).await;
        crate::srvstats::record_durwait(dur_t0.elapsed());
    }
    #[cfg(test)]
    crate::test_cut_points::hit_async(
        crate::test_cut_points::CutPoint::AppendPostDurablePreVisible,
        &st,
    )
    .await;

    if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
        ret!(text_response(404, "stream not found"), Conflict);
    }

    // Durable now (wal) / page-cache written (memory): expose the new bytes to
    // readers, mirroring the close-visibility ordering below.
    if let Some(t) = new_tail {
        publish_durable_tail(&store, &st, t, &wire);
    }

    // Closure ordering: WAL fsync → durable meta commit → expose the closure to
    // readers (closed_durable) and wake waiters. Readers never observe EOF for a
    // closure that is not yet durable (PROTOCOL.md §4.1).
    // Producer/access updates are debounced (documented crash window; see store::Meta).
    if close_req {
        if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
            ret!(text_response(404, "stream not found"), Conflict);
        }
        let st2 = st.clone();
        let meta_res = tokio::task::spawn_blocking(move || write_meta_sync(&st2, true)).await;
        if !matches!(meta_res, Ok(Ok(()))) {
            ret!(text_response(500, "close not durable"), Conflict);
        }
        if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
            ret!(text_response(404, "stream not found"), Conflict);
        }
        let tail = {
            let mut s = st.shared.write().unwrap();
            s.closed_durable = true;
            s.durable_tail
        };
        st.tail_tx.send_replace(Tail {
            bytes: tail,
            closed: true,
        });
        store.publish_inventory_tail(&st);
        #[cfg(target_os = "linux")]
        crate::sse_reactor::wake_stream(&st);
    } else if staged_lsn.is_some() {
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
    } else if meta_persist_needed {
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
        if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
            ret!(text_response(404, "stream not found"), Conflict);
        }
        maybe_seal_bg(&store, &st);
    }
    if notify_subscriptions && new_tail.is_some() {
        if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
            ret!(text_response(404, "stream not found"), Conflict);
        }
        store
            .subscriptions
            .clone()
            .on_stream_append(store.clone(), &st.path)
            .await;
    }

    if st.fenced.load(std::sync::atomic::Ordering::Acquire) {
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
    (b.body(empty()), Accept, is_json)
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
    let st = match store.registered_stream(&path) {
        Some(s) => s,
        None => return text_response(404, "stream not found"),
    };
    let st = match store.request_liveness(st, true).await {
        RequestLiveness::Live(st) => st,
        RequestLiveness::Gone => return gone(),
        RequestLiveness::Missing => return text_response(404, "stream not found"),
    };
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
    let end = t.bytes;
    // In sentinel mode (offset=now or a beyond-tail offset) the range is empty
    // (`start == end == tail`); report the resolved next offset — the requested
    // offset for a beyond-tail read (PROTOCOL.md §5.5). Otherwise report the
    // tail reached by the catch-up read.
    let reported = if now_mode { next_offset } else { end };
    // No ETag for offset=now (§10.1) — it's a tail sentinel, not a cacheable range.
    let etag = (!now_mode).then(|| st.etag(start, end, t.closed));
    if let Some(etag) = &etag {
        if header_str(req, "if-none-match") == Some(etag.as_str()) {
            let mut b = ResponseBuilder::new(304)
                .h("etag", etag.clone())
                .h(H_NEXT_OFFSET, format_offset(reported))
                .hs(H_UP_TO_DATE, "true");
            if t.closed {
                b = b.hs(H_CLOSED, "true");
            }
            return b.body(empty());
        }
    }
    // Catch-up read of historical bytes: not a live tail feed.
    let body = read_range_body(&st, start, end, false, "catchup", cache_hit).await;
    let mut b = ResponseBuilder::new(200)
        .h("content-type", st.config.content_type.clone())
        .h(H_NEXT_OFFSET, format_offset(reported))
        .hs(H_UP_TO_DATE, "true")
        .h(
            "cache-control",
            if now_mode {
                "no-store".into()
            } else {
                CACHEABLE.to_string()
            },
        );
    if let Some(etag) = etag {
        b = b.h("etag", etag);
    }
    if t.closed {
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
    // Subscribe before observing the tail so a concurrent retirement wake cannot
    // be missed between the initial snapshot and the wait loop.
    let mut deletion = st.subscribe_deletion();
    #[cfg(test)]
    crate::test_cut_points::hit_async(crate::test_cut_points::CutPoint::DeletionWatchRecheck, &st)
        .await;
    if deletion_observed(&mut deletion) {
        return deletion_missing_response();
    }
    let t0 = st.tail();
    // A beyond-tail numeric offset is treated as caught-up at the tail (see
    // `resolve_start`), so it follows the normal wait path below.
    let from = resolve_start(offset, t0.bytes).start;
    let cursor = compute_cursor(client_cursor);

    // Existing data → return immediately. This is a backlog (the consumer was
    // behind the tail), so it may include cold historical bytes: not hot.
    if from < t0.bytes {
        return long_poll_data(
            &st,
            from,
            t0,
            client_cursor,
            false,
            cache_hit,
            &mut deletion,
        )
        .await;
    }
    if t0.closed {
        if deletion_observed(&mut deletion) {
            return deletion_missing_response();
        }
        return long_poll_close(t0.bytes, cursor);
    }

    // Wait for new data / closure / timeout.
    let mut rx = st.tail_tx.subscribe();
    let deadline = Instant::now() + long_poll_timeout_dur();
    loop {
        if deletion_observed(&mut deletion) {
            return deletion_missing_response();
        }
        let t = *rx.borrow_and_update();
        if t.bytes > from {
            // Caught-up consumer woken by new appends: freshly-written, hot.
            return long_poll_data(&st, from, t, client_cursor, true, cache_hit, &mut deletion)
                .await;
        }
        if t.closed {
            if deletion_observed(&mut deletion) {
                return deletion_missing_response();
            }
            return long_poll_close(t.bytes, cursor);
        }
        tokio::select! {
            biased;
            r = deletion.changed() => {
                let _ = r;
                return deletion_missing_response();
            }
            r = rx.changed() => {
                if r.is_err() {
                    if deletion_observed(&mut deletion) {
                        return deletion_missing_response();
                    }
                    let t = st.tail();
                    if t.bytes > from {
                        return long_poll_data(
                            &st,
                            from,
                            t,
                            client_cursor,
                            true,
                            cache_hit,
                            &mut deletion,
                        )
                        .await;
                    }
                    if deletion_observed(&mut deletion) {
                        return deletion_missing_response();
                    }
                    return long_poll_timeout(t.bytes, cursor, t.closed);
                }
            }
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
                if deletion_observed(&mut deletion) {
                    return deletion_missing_response();
                }
                let t = st.tail();
                if t.bytes > from {
                    return long_poll_data(
                        &st,
                        from,
                        t,
                        client_cursor,
                        true,
                        cache_hit,
                        &mut deletion,
                    )
                    .await;
                }
                if deletion_observed(&mut deletion) {
                    return deletion_missing_response();
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
    deletion: &mut watch::Receiver<bool>,
) -> Resp {
    if deletion_observed(deletion) {
        return deletion_missing_response();
    }
    let cursor = compute_cursor(client_cursor);
    let body = read_range_body(st, from, t.bytes, hot, "long-poll", cache_hit).await;
    if deletion_observed(deletion) {
        return deletion_missing_response();
    }
    let mut b = ResponseBuilder::new(200)
        .h("content-type", st.config.content_type.clone())
        .h(H_NEXT_OFFSET, format_offset(t.bytes))
        .h(H_CURSOR, cursor.to_string())
        .h("etag", st.etag(from, t.bytes, t.closed))
        .hs(H_UP_TO_DATE, "true")
        .hs("cache-control", CACHEABLE);
    if t.closed {
        b = b.hs(H_CLOSED, "true");
    }
    b.body(body)
}

fn deletion_observed(deletion: &mut watch::Receiver<bool>) -> bool {
    *deletion.borrow_and_update()
}

fn deletion_missing_response() -> Resp {
    text_response(404, "stream not found")
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
    deletion: watch::Receiver<bool>,
    pos: u64,
    start: u64,
    deadline: Instant,
    client_cursor: Option<u64>,
    encoding: SseEncoding,
    sent_initial: bool,
    done: bool,
}

impl SseSource {
    fn deletion_observed(&mut self) -> bool {
        *self.deletion.borrow_and_update()
    }

    /// Produce the next SSE event, or `None` to end the stream. Mirrors the
    /// original producer loop, but returns one frame per call (state persists in
    /// `self`) so it can run inline without a channel.
    async fn next(&mut self) -> Option<Bytes> {
        if self.done || self.deletion_observed() {
            self.done = true;
            return None;
        }
        loop {
            if self.deletion_observed() {
                self.done = true;
                return None;
            }
            let t = *self.rxw.borrow_and_update();
            if t.bytes > self.pos {
                // Read new range and emit data + control. Caught-up subscribers
                // share the resident tail chunk — one read for all of them —
                // and fall back to a file read only when behind it.
                let read_t0 = crate::telemetry::Timer::start();
                let cache_hit;
                let data = match self.st.tail_chunk_slice(self.pos, t.bytes) {
                    Some(b) => {
                        cache_hit = true;
                        b
                    }
                    None => {
                        cache_hit = false;
                        match read_range_bytes(&self.st, self.pos, t.bytes).await {
                            Ok(d) => d,
                            // End the stream without advancing `pos`: the client
                            // reconnects from its last offset, never skipping a gap.
                            Err(_) => {
                                self.done = true;
                                return None;
                            }
                        }
                    }
                };
                if self.deletion_observed() {
                    self.done = true;
                    return None;
                }
                crate::telemetry::record_tail_cache(cache_hit, "sse");
                crate::telemetry::record_read(read_t0.elapsed_secs(), "sse", cache_hit);
                let mut ev = String::new();
                sse_encode_data(&mut ev, &data, self.encoding);
                self.pos = t.bytes;
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
                if self.deletion_observed() {
                    self.done = true;
                    return None;
                }
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
                if self.deletion_observed() {
                    self.done = true;
                    return None;
                }
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
                biased;
                r = self.deletion.changed() => {
                    let _ = r;
                    self.done = true;
                    return None;
                }
                r = self.rxw.changed() => {
                    if r.is_err() {
                        self.done = true;
                        return None;
                    }
                }
                _ = tokio::time::sleep(wait) => {
                    if self.deletion_observed() {
                        self.done = true;
                        return None;
                    }
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
        if *self.deletion.borrow() {
            return None;
        }
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
        deletion: st.subscribe_deletion(),
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
    let st = match store.registered_stream(&path) {
        Some(s) => s,
        None => return text_response(404, "stream not found"),
    };
    let st = match store.request_liveness(st, false).await {
        RequestLiveness::Live(st) => st,
        RequestLiveness::Gone => return gone(),
        RequestLiveness::Missing => return text_response(404, "stream not found"),
    };
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
    let st = match store.registered_stream(&path) {
        Some(s) => s,
        None => return text_response(404, "stream not found"),
    };
    if st.shared.read().unwrap().soft_deleted {
        return gone();
    }
    let expired_at_dispatch = st.is_expired_at(SystemTime::now());
    match store.retire_explicit(st).await {
        ExplicitRetirementResult::Owner(_) if expired_at_dispatch => {
            text_response(404, "stream not found")
        }
        ExplicitRetirementResult::Owner(ticket) => match ticket.wait_first_attempt().await {
            crate::retirement::FirstAttemptCompletion::Succeeded { .. } => {
                ResponseBuilder::new(204).body(empty())
            }
            crate::retirement::FirstAttemptCompletion::Failed
            | crate::retirement::FirstAttemptCompletion::Cancelled => retirement_retry_after("1"),
        },
        ExplicitRetirementResult::Missing => text_response(404, "stream not found"),
        ExplicitRetirementResult::Gone => gone(),
        ExplicitRetirementResult::Rejected(crate::retirement::RetirementAdmission::CoolingDown) => {
            retirement_retry_after("60")
        }
        ExplicitRetirementResult::Existing(_)
        | ExplicitRetirementResult::Rejected(_)
        | ExplicitRetirementResult::Unavailable
        | ExplicitRetirementResult::Renewed(_)
        | ExplicitRetirementResult::Cancelled(_)
        | ExplicitRetirementResult::Stale => retirement_retry_after("1"),
    }
}

fn retirement_retry_after(seconds: &'static str) -> Resp {
    ResponseBuilder::new(503)
        .hs("retry-after", seconds)
        .body(empty())
}

#[cfg(test)]
mod deletion_wakes_tests {
    use super::*;
    use crate::store::{CreateResult, Store, StreamConfig};
    use crate::tier::TierConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::timeout;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn directory(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ds-deletion-wakes-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config() -> StreamConfig {
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

    fn state(tag: &str) -> (std::path::PathBuf, Arc<StreamState>) {
        let directory = directory(tag);
        let store = Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap();
        let state = match store.create("stream", config(), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        (directory, state)
    }

    fn inline_source(st: Arc<StreamState>) -> SseSource {
        SseSource {
            rxw: st.tail_tx.subscribe(),
            deletion: st.subscribe_deletion(),
            st,
            pos: 0,
            start: 0,
            deadline: Instant::now() + SSE_MAX_DURATION,
            client_cursor: None,
            encoding: SseEncoding::Base64,
            sent_initial: false,
            done: false,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deletion_wakes_long_poll_already_signaled() {
        let (directory, state) = state("long-poll-already");
        state.signal_deletion();

        let mut cache_hit = false;
        assert_eq!(
            handle_long_poll(state, ParsedOffset::Now, None, &mut cache_hit)
                .await
                .status,
            404
        );

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deletion_wakes_long_poll_subscribe_then_recheck_without_a_lost_wakeup() {
        let (directory, state) = state("long-poll-wait");
        let pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::DeletionWatchRecheck,
            &state,
        );
        let waiting_state = state.clone();
        let waiting = tokio::spawn(async move {
            let mut cache_hit = false;
            handle_long_poll(waiting_state, ParsedOffset::Now, None, &mut cache_hit).await
        });

        pause.wait_until_held().await;
        state.signal_deletion();
        pause.release();
        assert_eq!(
            timeout(Duration::from_secs(5), waiting)
                .await
                .expect("deletion must wake long-poll")
                .unwrap()
                .status,
            404
        );

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deletion_wakes_inline_sse_already_signaled() {
        let (directory, state) = state("sse-already");
        state.signal_deletion();
        let mut source = inline_source(state);

        assert!(source.next().await.is_none());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deletion_wakes_inline_sse_mid_wait_without_post_delete_event() {
        let (directory, state) = state("sse-wait");
        let mut source = inline_source(state.clone());
        assert!(source.next().await.is_some(), "initial control event");

        let signal_state = state.clone();
        let signal = tokio::spawn(async move {
            tokio::task::yield_now().await;
            signal_state.signal_deletion();
        });
        assert!(timeout(Duration::from_secs(5), source.next())
            .await
            .expect("deletion must wake inline SSE")
            .is_none());
        signal.await.unwrap();
        assert!(source.next().await.is_none(), "no post-delete event");

        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod explicit_delete_handler_tests {
    use super::*;
    use crate::retirement::RetirementConfig;
    use crate::store::{
        set_delete_fault_for, CreateResult, InflightAppendGuard, Store, StreamConfig,
        DELETE_FAULT_LOCK,
    };
    use crate::tier::TierConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::timeout;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct DeleteFaultReset(Arc<StreamState>);

    impl Drop for DeleteFaultReset {
        fn drop(&mut self) {
            set_delete_fault_for(&self.0, 0);
        }
    }

    fn directory(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ds-explicit-delete-handler-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config(expires_at: Option<SystemTime>) -> StreamConfig {
        config_with_ttl(None, expires_at)
    }

    fn config_with_ttl(ttl_seconds: Option<u64>, expires_at: Option<SystemTime>) -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds,
            expires_at,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn store(tag: &str) -> (std::path::PathBuf, Arc<Store>) {
        let directory = directory(tag);
        let _ = std::fs::remove_dir_all(&directory);
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        (directory, store)
    }

    fn create(store: &Store, path: &str, expires_at: Option<SystemTime>) -> Arc<StreamState> {
        create_with_config(store, path, config(expires_at))
    }

    fn create_with_config(store: &Store, path: &str, config: StreamConfig) -> Arc<StreamState> {
        match store.create(path, config, None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected stream creation"),
        }
    }

    fn request(method: Method, path: &str) -> Req {
        Req {
            method,
            path: path.into(),
            query: None,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    fn retry_after(response: &Resp) -> Option<&str> {
        response
            .headers
            .iter()
            .find(|(name, _)| *name == "retry-after")
            .map(|(_, value)| value.as_str())
    }

    async fn wait_fenced(stream: &StreamState) {
        timeout(Duration::from_secs(5), async {
            while !stream.fenced.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retirement must fence the stream");
    }

    async fn wait_for_removal(stream: &StreamState) {
        timeout(Duration::from_secs(5), async {
            while stream.file_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background cleanup must remove the stream");
    }

    async fn wait_for_parent_refcount(parent: &StreamState, ref_count: u32) {
        let meta = crate::store::meta_path(&parent.file_path);
        timeout(Duration::from_secs(5), async {
            loop {
                let persisted = std::fs::read(&meta)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<crate::store::Meta>(&bytes).ok())
                    .is_some_and(|meta| meta.ref_count == ref_count);
                if persisted {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("parent refcount must be persisted");
    }

    async fn shutdown(store: &Store) {
        if let Some(executor) = store.retirement_executor() {
            executor.shutdown().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_hard_success_waits_for_durable_cleanup() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("hard-success");
        store.init_retirement_executor().unwrap();
        let stream = create(&store, "stream", None);

        let response = handle_delete(store.clone(), "stream".into()).await;

        assert_eq!(response.status, 204);
        assert!(retry_after(&response).is_none());
        assert!(!stream.file_path.exists());
        assert!(store.registered_stream("stream").is_none());
        shutdown(&store).await;
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_fork_child_cleanup_enters_runtime_for_parent_release() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("fork-child");
        store.init_retirement_executor().unwrap();
        let parent = create(&store, "parent", None);
        let child = match store
            .create("child", config(None), Some(parent.clone()), 0)
            .unwrap()
        {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected fork child creation"),
        };
        assert_eq!(parent.shared.read().unwrap().ref_count, 1);

        assert_eq!(
            handle_delete(store.clone(), "child".into()).await.status,
            204
        );
        assert_eq!(parent.shared.read().unwrap().ref_count, 0);
        wait_for_parent_refcount(&parent, 0).await;
        shutdown(&store).await;
        drop(child);
        drop(parent);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_soft_success_persists_tombstone() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("soft-success");
        store.init_retirement_executor().unwrap();
        let stream = create(&store, "stream", None);
        stream.shared.write().unwrap().ref_count = 1;

        let response = handle_delete(store.clone(), "stream".into()).await;

        assert_eq!(response.status, 204);
        assert!(stream.file_path.exists());
        assert!(
            store
                .registered_stream("stream")
                .unwrap()
                .shared
                .read()
                .unwrap()
                .soft_deleted
        );
        shutdown(&store).await;
        drop(stream);
        drop(store);
        let reopened = Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap();
        assert!(
            reopened
                .registered_stream("stream")
                .unwrap()
                .shared
                .read()
                .unwrap()
                .soft_deleted
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_first_failure_returns_retry_then_retries() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("retry");
        let retirement = RetirementConfig {
            retry_base: Duration::from_millis(1),
            ..RetirementConfig::default()
        };
        store.init_retirement_executor_for_test(retirement).unwrap();
        let stream = create(&store, "stream", None);
        let _reset = DeleteFaultReset(stream.clone());
        set_delete_fault_for(&stream, 2);

        let response = handle_delete(store.clone(), "stream".into()).await;

        assert_eq!(response.status, 503);
        assert_eq!(retry_after(&response), Some("1"));
        assert!(stream.fenced.load(Ordering::Acquire));
        assert!(stream.file_path.exists());
        set_delete_fault_for(&stream, 0);
        wait_for_removal(&stream).await;
        shutdown(&store).await;
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_duplicate_is_retryable_while_owner_waits() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("duplicate");
        store.init_retirement_executor().unwrap();
        let stream = create(&store, "stream", None);
        let appender = stream.appender.lock().await;
        let guard = InflightAppendGuard::begin(&stream, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner = tokio::spawn(async move { handle_delete(owner_store, "stream".into()).await });
        wait_fenced(&stream).await;

        let duplicate = handle_delete(store.clone(), "stream".into()).await;
        assert_eq!(duplicate.status, 503);
        assert_eq!(retry_after(&duplicate), Some("1"));
        drop(guard);
        assert_eq!(
            timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .status,
            204
        );
        shutdown(&store).await;
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_queue_full_has_no_fallback() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("queue-full");
        let retirement = RetirementConfig {
            queue_capacity: 1,
            ..RetirementConfig::default()
        };
        store.init_retirement_executor_for_test(retirement).unwrap();
        let first = create(&store, "first", None);
        let second = create(&store, "second", None);
        let appender = first.appender.lock().await;
        let guard = InflightAppendGuard::begin(&first, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner = tokio::spawn(async move { handle_delete(owner_store, "first".into()).await });
        wait_fenced(&first).await;

        let response = handle_delete(store.clone(), "second".into()).await;
        assert_eq!(response.status, 503);
        assert_eq!(retry_after(&response), Some("1"));
        assert!(second.file_path.exists());
        assert!(store.registered_stream("second").is_some());
        drop(guard);
        assert_eq!(
            timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .status,
            204
        );
        shutdown(&store).await;
        drop(first);
        drop(second);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_due_owner_is_not_a_duplicate_success() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("due");
        store.init_retirement_executor().unwrap();
        let stream = create(&store, "stream", Some(SystemTime::UNIX_EPOCH));
        let appender = stream.appender.lock().await;
        let guard = InflightAppendGuard::begin(&stream, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner = tokio::spawn(async move { handle_delete(owner_store, "stream".into()).await });
        wait_fenced(&stream).await;

        let duplicate = handle_delete(store.clone(), "stream".into()).await;
        assert_eq!(duplicate.status, 503);
        assert_eq!(retry_after(&duplicate), Some("1"));
        drop(guard);
        assert_eq!(
            timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .status,
            404
        );
        wait_for_removal(&stream).await;
        shutdown(&store).await;
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_delete_handler_maps_missing_gone_and_unavailable() {
        let (missing_directory, missing_store) = store("missing");
        assert_eq!(
            handle_delete(missing_store.clone(), "stream".into())
                .await
                .status,
            404
        );
        drop(missing_store);
        let _ = std::fs::remove_dir_all(missing_directory);

        let (gone_directory, gone_store) = store("gone");
        let gone = create(&gone_store, "stream", None);
        gone.shared.write().unwrap().soft_deleted = true;
        assert_eq!(
            handle_delete(gone_store.clone(), "stream".into())
                .await
                .status,
            410
        );
        drop(gone);
        drop(gone_store);
        let _ = std::fs::remove_dir_all(gone_directory);

        let (directory, store) = store("unavailable");
        let stream = create(&store, "stream", None);
        let response = handle_delete(store.clone(), "stream".into()).await;
        assert_eq!(response.status, 503);
        assert_eq!(retry_after(&response), Some("1"));
        assert!(stream.file_path.exists());
        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_expiry_get_touches_and_head_does_not() {
        let (directory, store) = store("live-touch");
        store.init_retirement_executor().unwrap();
        let get_stream = create_with_config(&store, "get", config_with_ttl(Some(3_600), None));
        let head_stream = create_with_config(&store, "head", config_with_ttl(Some(3_600), None));
        let before = SystemTime::now() - Duration::from_secs(1);
        get_stream.shared.write().unwrap().last_access = before;
        head_stream.shared.write().unwrap().last_access = before;

        assert_eq!(
            handle(store.clone(), request(Method::Get, "get"))
                .await
                .status,
            200
        );
        assert!(get_stream.shared.read().unwrap().last_access > before);
        assert!(get_stream.meta_dirty.load(Ordering::Acquire));
        assert_eq!(
            handle(store.clone(), request(Method::Head, "head"))
                .await
                .status,
            200
        );
        assert_eq!(head_stream.shared.read().unwrap().last_access, before);
        assert!(!head_stream.meta_dirty.load(Ordering::Acquire));
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_expiry_get_and_head_retire_without_waiting_for_cleanup() {
        let (directory, store) = store("expired");
        store.init_retirement_executor().unwrap();
        let get_stream = create(&store, "get", Some(SystemTime::UNIX_EPOCH));
        let head_stream = create(&store, "head", Some(SystemTime::UNIX_EPOCH));

        assert_eq!(
            handle(store.clone(), request(Method::Get, "get"))
                .await
                .status,
            404
        );
        assert!(get_stream.fenced.load(Ordering::Acquire));
        assert_eq!(
            handle(store.clone(), request(Method::Head, "head"))
                .await
                .status,
            404
        );
        assert!(head_stream.fenced.load(Ordering::Acquire));
        wait_for_removal(&get_stream).await;
        wait_for_removal(&head_stream).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_expiry_queue_full_has_no_direct_fallback() {
        let (directory, store) = store("queue-full-expiry");
        store
            .init_retirement_executor_for_test(RetirementConfig {
                queue_capacity: 1,
                ..RetirementConfig::default()
            })
            .unwrap();
        let first = create(&store, "first", Some(SystemTime::UNIX_EPOCH));
        let second = create(&store, "second", Some(SystemTime::UNIX_EPOCH));
        let appender = first.appender.lock().await;
        let guard = InflightAppendGuard::begin(&first, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner =
            tokio::spawn(async move { handle(owner_store, request(Method::Get, "first")).await });
        wait_fenced(&first).await;

        assert_eq!(
            handle(store.clone(), request(Method::Get, "second"))
                .await
                .status,
            404
        );
        assert!(!second.fenced.load(Ordering::Acquire));
        assert!(second.file_path.exists());
        drop(guard);
        assert_eq!(
            timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .status,
            404
        );
        wait_for_removal(&first).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_expiry_soft_tombstone_is_gone_for_get_and_head() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = store("soft-tombstone");
        store.init_retirement_executor().unwrap();
        let stream = create(&store, "stream", None);
        stream.shared.write().unwrap().ref_count = 1;
        assert_eq!(
            handle_delete(store.clone(), "stream".into()).await.status,
            204
        );
        assert!(store.registered_stream("stream").is_some());
        assert!(stream.fenced.load(Ordering::Acquire));
        assert!(stream.shared.read().unwrap().soft_deleted);

        assert_eq!(
            handle(store.clone(), request(Method::Get, "stream"))
                .await
                .status,
            410
        );
        assert_eq!(
            handle(store.clone(), request(Method::Head, "stream"))
                .await
                .status,
            410
        );
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_expiry_liveness_loses_to_an_exact_fence_without_touching_ttl() {
        let (directory, store) = store("fence-race");
        let executor = store.init_retirement_executor().unwrap().clone();
        let stream = create_with_config(&store, "stream", config_with_ttl(Some(1), None));
        let before = SystemTime::UNIX_EPOCH;
        stream.shared.write().unwrap().last_access = before;
        let pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::FenceAfterAppenderTransition,
            &stream,
        );
        let owner_store = store.clone();
        let owner_stream = stream.clone();
        let owner = tokio::spawn(async move { owner_store.retire_expiry(owner_stream).await });

        pause.wait_until_held().await;
        assert!(stream.fenced.load(Ordering::Acquire));
        assert_eq!(executor.snapshot().total_jobs, 1);
        assert!(matches!(
            store.request_liveness(stream.clone(), true).await,
            crate::store::RequestLiveness::Missing
        ));
        assert_eq!(stream.shared.read().unwrap().last_access, before);
        assert!(!stream.meta_dirty.load(Ordering::Acquire));
        pause.release();

        let ticket = match timeout(Duration::from_secs(5), owner)
            .await
            .expect("fenced retirement must resume")
            .expect("retirement task should not panic")
        {
            crate::store::ExplicitRetirementResult::Owner(ticket) => ticket,
            _ => panic!("due expiry must retain the exact fenced owner"),
        };
        assert!(matches!(
            ticket.wait_terminal().await,
            crate::retirement::TerminalCleanupCompletion::Succeeded { .. }
        ));
        assert_eq!(executor.snapshot().total_jobs, 0);
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ttl_touch_before_exact_fence_renews_and_retains_the_live_identity() {
        let (directory, store) = store("renew-before-fence");
        let executor = store.init_retirement_executor().unwrap().clone();
        let stream = create_with_config(&store, "stream", config_with_ttl(Some(1), None));
        stream.shared.write().unwrap().last_access = SystemTime::UNIX_EPOCH;
        let pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::FenceBeforeAppenderTransition,
            &stream,
        );
        let owner_store = store.clone();
        let owner_stream = stream.clone();
        let owner =
            tokio::spawn(async move { owner_store.retire_proactive_expiry(owner_stream).await });

        pause.wait_until_held().await;
        // A TTL-mutating operation that won the appender before this scanner
        // pass's exact fence recheck renews the deadline. `request_liveness`
        // intentionally refuses an already-expired target, so model the
        // already-admitted touch at its actual serialization boundary.
        let appender = stream.appender.lock().await;
        stream.touch_at(SystemTime::now());
        drop(appender);
        assert!(!stream.fenced.load(Ordering::Acquire));
        assert!(stream.shared.read().unwrap().last_access > SystemTime::UNIX_EPOCH);
        pause.release();

        let ticket = match timeout(Duration::from_secs(5), owner)
            .await
            .expect("renewed retirement must resume")
            .expect("retirement task should not panic")
        {
            crate::store::ExplicitRetirementResult::Renewed(ticket) => ticket,
            _ => panic!("only the appender-locked recheck may report renewal"),
        };
        assert_eq!(
            ticket.wait_logical().await,
            crate::retirement::LogicalCompletion::Cancelled
        );
        assert_eq!(
            ticket.wait_terminal().await,
            crate::retirement::TerminalCleanupCompletion::Cancelled
        );
        assert!(store
            .registered_stream("stream")
            .is_some_and(|current| Arc::ptr_eq(&current, &stream)));
        assert!(store
            .inventory_page(None, None, 10)
            .unwrap()
            .1
            .iter()
            .any(|entry| entry.path == "stream"));
        assert_eq!(executor.snapshot().total_jobs, 0);
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod fork_source_liveness_tests {
    use super::*;
    use crate::retirement::RetirementConfig;
    use crate::store::{CreateResult, InflightAppendGuard, Store, StreamConfig};
    use crate::tier::TierConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::UNIX_EPOCH;
    use tokio::time::timeout;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn directory(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ds-fork-source-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config(ttl_seconds: Option<u64>) -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn store(tag: &str) -> (std::path::PathBuf, Arc<Store>) {
        let directory = directory(tag);
        let _ = std::fs::remove_dir_all(&directory);
        (
            directory.clone(),
            Arc::new(Store::new_with_tier(directory, TierConfig::default()).unwrap()),
        )
    }

    fn create(store: &Store, path: &str, ttl_seconds: Option<u64>) -> Arc<StreamState> {
        match store.create(path, config(ttl_seconds), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected fresh stream"),
        }
    }

    fn fork_put(source: &str, target: &str) -> Req {
        Req {
            method: Method::Put,
            path: target.into(),
            query: None,
            headers: vec![
                ("content-type".into(), "application/octet-stream".into()),
                (H_FORKED_FROM.into(), source.into()),
            ],
            body: Bytes::new(),
        }
    }

    async fn wait_fenced(stream: &StreamState) {
        timeout(Duration::from_secs(5), async {
            while !stream.fenced.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retirement must fence the exact source");
    }

    async fn wait_removed(stream: &StreamState) {
        timeout(Duration::from_secs(5), async {
            while stream.file_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded cleanup must remove the source");
    }

    async fn shutdown(store: &Store) {
        if let Some(executor) = store.retirement_executor() {
            executor.shutdown().await;
        }
    }

    fn retry_after(response: &Resp) -> Option<&str> {
        response
            .headers
            .iter()
            .find(|(name, _)| *name == "retry-after")
            .map(|(_, value)| value.as_str())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fork_expired_source_retires_boundedly_and_saturation_has_no_fallback() {
        let (directory, store) = store("expiry");
        store
            .init_retirement_executor_for_test(RetirementConfig {
                queue_capacity: 1,
                ..RetirementConfig::default()
            })
            .unwrap();
        let first = create(&store, "first", Some(1));
        let second = create(&store, "second", Some(1));
        first.shared.write().unwrap().last_access = UNIX_EPOCH;
        second.shared.write().unwrap().last_access = UNIX_EPOCH;
        let appender = first.appender.lock().await;
        let guard = InflightAppendGuard::begin(&first, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner =
            tokio::spawn(async move { handle(owner_store, fork_put("first", "child-a")).await });
        wait_fenced(&first).await;

        assert_eq!(
            handle(store.clone(), fork_put("second", "child-b"))
                .await
                .status,
            404
        );
        assert!(!second.fenced.load(Ordering::Acquire));
        assert!(second.file_path.exists());
        assert!(store.registered_stream("child-b").is_none());
        drop(guard);
        assert_eq!(
            timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .status,
            404
        );
        wait_removed(&first).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fork_soft_source_is_conflict_and_source_ttl_is_never_touched() {
        let (directory, store) = store("soft-and-ttl");
        store.init_retirement_executor().unwrap();
        let source = create(&store, "source", Some(3_600));
        let before = SystemTime::now() - Duration::from_secs(10);
        source.shared.write().unwrap().last_access = before;
        assert_eq!(
            handle(store.clone(), fork_put("source", "child"))
                .await
                .status,
            201
        );
        assert_eq!(source.shared.read().unwrap().last_access, before);
        assert_eq!(source.shared.read().unwrap().ref_count, 1);

        assert!(matches!(
            store.retire_explicit(source.clone()).await,
            ExplicitRetirementResult::Owner(_)
        ));
        assert!(source.shared.read().unwrap().soft_deleted);
        assert_eq!(
            handle(store.clone(), fork_put("source", "child-2"))
                .await
                .status,
            409
        );
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fork_waiting_for_source_appender_loses_to_fence_without_creating() {
        let (directory, store) = store("fence");
        let source = create(&store, "source", None);
        let appender = source.appender.lock().await;
        let waiting_store = store.clone();
        let waiting =
            tokio::spawn(async move { handle(waiting_store, fork_put("source", "child")).await });
        tokio::task::yield_now().await;
        source.fence_while_holding_appender(&appender);
        drop(appender);

        assert_eq!(
            timeout(Duration::from_secs(5), waiting)
                .await
                .unwrap()
                .unwrap()
                .status,
            404
        );
        assert_eq!(source.shared.read().unwrap().ref_count, 0);
        assert!(store.registered_stream("child").is_none());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fork_self_target_expiry_returns_retry_without_waiting_on_its_lease() {
        let (directory, store) = store("self-expiry");
        store.init_retirement_executor().unwrap();
        let source = create(&store, "self-source", Some(3_600));
        let pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::ForkSourceLease,
            &source,
        );
        let fork_store = store.clone();
        let self_fork = tokio::spawn(async move {
            handle(fork_store, fork_put("self-source", "self-source")).await
        });
        pause.wait_until_held().await;
        source.shared.write().unwrap().last_access = UNIX_EPOCH;
        pause.release();

        let response = timeout(Duration::from_secs(5), self_fork)
            .await
            .expect("self-fork must not wait on its own source lease")
            .unwrap();
        assert_eq!(response.status, 503);
        assert_eq!(retry_after(&response), Some("1"));
        assert!(!source.fenced.load(Ordering::Acquire));
        assert!(Arc::ptr_eq(
            &store.registered_stream("self-source").unwrap(),
            &source
        ));
        assert_eq!(source.shared.read().unwrap().ref_count, 0);

        assert_eq!(
            handle(store.clone(), fork_put("self-source", "child"))
                .await
                .status,
            404
        );
        wait_removed(&source).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fork_source_lease_makes_retirement_observe_the_durable_parent_reference() {
        let (directory, store) = store("lease");
        store.init_retirement_executor().unwrap();
        let source = create(&store, "source-lease", None);
        let pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::ForkSourceLease,
            &source,
        );
        let fork_store = store.clone();
        let fork = tokio::spawn(async move {
            handle(fork_store, fork_put("source-lease", "child-lease")).await
        });
        pause.wait_until_held().await;

        let delete_store = store.clone();
        let deleting =
            tokio::spawn(async move { handle_delete(delete_store, "source-lease".into()).await });
        wait_fenced(&source).await;
        assert_eq!(source.shared.read().unwrap().ref_count, 0);
        assert!(store.registered_stream("child-lease").is_none());
        pause.release();

        assert_eq!(
            timeout(Duration::from_secs(5), fork)
                .await
                .unwrap()
                .unwrap()
                .status,
            201
        );
        assert_eq!(
            timeout(Duration::from_secs(5), deleting)
                .await
                .unwrap()
                .unwrap()
                .status,
            204
        );
        assert_eq!(source.shared.read().unwrap().ref_count, 1);
        assert!(source.shared.read().unwrap().soft_deleted);
        assert!(source.file_path.exists());
        let child = store.registered_stream("child-lease").unwrap();
        assert!(Arc::ptr_eq(child.parent.as_ref().unwrap(), &source));
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fork_target_conflict_drops_lease_and_allows_hard_source_cleanup() {
        let (directory, store) = store("target-conflict");
        store.init_retirement_executor().unwrap();
        let source = create(&store, "source-conflict", None);
        let _target = create(&store, "child-conflict", None);
        let pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::ForkSourceLease,
            &source,
        );
        let fork_store = store.clone();
        let fork = tokio::spawn(async move {
            handle(fork_store, fork_put("source-conflict", "child-conflict")).await
        });
        pause.wait_until_held().await;
        let delete_store = store.clone();
        let deleting =
            tokio::spawn(
                async move { handle_delete(delete_store, "source-conflict".into()).await },
            );
        wait_fenced(&source).await;
        pause.release();

        assert_eq!(
            timeout(Duration::from_secs(5), fork)
                .await
                .unwrap()
                .unwrap()
                .status,
            409
        );
        assert_eq!(
            timeout(Duration::from_secs(5), deleting)
                .await
                .unwrap()
                .unwrap()
                .status,
            204
        );
        assert_eq!(source.shared.read().unwrap().ref_count, 0);
        wait_removed(&source).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod target_put_tests {
    use super::*;
    use crate::retirement::RetirementConfig;
    use crate::store::{
        set_delete_fault_for, CreateResult, InflightAppendGuard, Store, StreamConfig,
        DELETE_FAULT_LOCK,
    };
    use crate::tier::TierConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::UNIX_EPOCH;
    use tokio::time::timeout;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn directory(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ds-target-put-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config(ttl_seconds: Option<u64>) -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn put(path: &str, ttl_seconds: Option<u64>, body: &'static [u8]) -> Req {
        let mut headers = vec![("content-type".into(), "application/octet-stream".into())];
        if let Some(ttl_seconds) = ttl_seconds {
            headers.push((H_TTL.into(), ttl_seconds.to_string()));
        }
        Req {
            method: Method::Put,
            path: path.into(),
            query: None,
            headers,
            body: Bytes::from_static(body),
        }
    }

    fn store(tag: &str) -> (std::path::PathBuf, Arc<Store>) {
        let directory = directory(tag);
        let _ = std::fs::remove_dir_all(&directory);
        (
            directory.clone(),
            Arc::new(Store::new_with_tier(directory, TierConfig::default()).unwrap()),
        )
    }

    fn create(store: &Store, path: &str, ttl_seconds: Option<u64>) -> Arc<StreamState> {
        match store.create(path, config(ttl_seconds), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected fresh stream"),
        }
    }

    fn retry_after(response: &Resp) -> Option<&str> {
        response
            .headers
            .iter()
            .find(|(name, _)| *name == "retry-after")
            .map(|(_, value)| value.as_str())
    }

    async fn wait_fenced(stream: &StreamState) {
        timeout(Duration::from_secs(5), async {
            while !stream.fenced.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retirement must fence its exact stream");
    }

    async fn wait_removed(stream: &StreamState) {
        timeout(Duration::from_secs(5), async {
            while stream.file_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("physical cleanup must finish");
    }

    async fn shutdown(store: &Store) {
        if let Some(executor) = store.retirement_executor() {
            executor.shutdown().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_put_compatible_ttl_touches_but_conflict_does_not() {
        let (directory, store) = store("compatible-touch");
        let stream = create(&store, "stream", Some(3_600));
        let before = SystemTime::now() - Duration::from_secs(10);
        stream.shared.write().unwrap().last_access = before;

        assert_eq!(
            handle(store.clone(), put("stream", Some(3_600), b""))
                .await
                .status,
            200
        );
        let touched = stream.shared.read().unwrap().last_access;
        assert!(touched > before);
        assert!(stream.meta_dirty.load(Ordering::Acquire));
        stream.meta_dirty.store(false, Ordering::Release);

        assert_eq!(
            handle(store.clone(), put("stream", None, b"")).await.status,
            409
        );
        assert_eq!(stream.shared.read().unwrap().last_access, touched);
        assert!(!stream.meta_dirty.load(Ordering::Acquire));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_put_expiry_recreates_before_failed_old_cleanup_can_touch_new_identity() {
        let _fault = DELETE_FAULT_LOCK.lock().await;
        let _durability = test_support::DurabilityGuard::memory();
        let (directory, store) = store("expiry-recreate");
        store
            .init_retirement_executor_for_test(RetirementConfig {
                retry_base: Duration::from_millis(1),
                ..RetirementConfig::default()
            })
            .unwrap();
        let old = create(&store, "stream", Some(1));
        old.shared.write().unwrap().last_access = UNIX_EPOCH;
        set_delete_fault_for(&old, 2);

        let response = handle(store.clone(), put("stream", None, b"new")).await;
        assert_eq!(response.status, 201);
        let new = store.registered_stream("stream").unwrap();
        assert_ne!(new.id, old.id);
        assert!(new.file_path.exists());
        assert_eq!(new.tail().bytes, 3);
        assert!(old.fenced.load(Ordering::Acquire));
        set_delete_fault_for(&old, 0);
        wait_removed(&old).await;
        assert!(Arc::ptr_eq(
            &store.registered_stream("stream").unwrap(),
            &new
        ));
        assert!(new.file_path.exists());
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_put_duplicate_and_queue_full_are_retryable_without_fallback() {
        let _durability = test_support::DurabilityGuard::memory();
        let (directory, store) = store("duplicate-queue");
        store
            .init_retirement_executor_for_test(RetirementConfig {
                queue_capacity: 1,
                ..RetirementConfig::default()
            })
            .unwrap();
        let first = create(&store, "first", Some(1));
        let second = create(&store, "second", Some(1));
        first.shared.write().unwrap().last_access = UNIX_EPOCH;
        second.shared.write().unwrap().last_access = UNIX_EPOCH;
        let appender = first.appender.lock().await;
        let guard = InflightAppendGuard::begin(&first, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner = tokio::spawn(async move { handle(owner_store, put("first", None, b"")).await });
        wait_fenced(&first).await;

        let duplicate = handle(store.clone(), put("first", None, b"")).await;
        assert_eq!(duplicate.status, 503);
        assert_eq!(retry_after(&duplicate), Some("1"));
        let saturated = handle(store.clone(), put("second", None, b"")).await;
        assert_eq!(saturated.status, 503);
        assert_eq!(retry_after(&saturated), Some("1"));
        assert!(!second.fenced.load(Ordering::Acquire));
        assert!(second.file_path.exists());
        drop(guard);
        assert_eq!(
            timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .status,
            201
        );
        wait_removed(&first).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_put_retained_soft_tombstone_is_conflict() {
        let (directory, store) = store("soft-tombstone");
        store.init_retirement_executor().unwrap();
        let stream = create(&store, "stream", None);
        stream.shared.write().unwrap().ref_count = 1;
        assert!(matches!(
            store.retire_explicit(stream.clone()).await,
            ExplicitRetirementResult::Owner(_)
        ));
        assert!(stream.shared.read().unwrap().soft_deleted);
        assert_eq!(
            handle(store.clone(), put("stream", None, b"")).await.status,
            409
        );
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_put_waiting_for_appender_loses_to_fence_without_touching() {
        let (directory, store) = store("fence-race");
        let stream = create(&store, "stream", Some(3_600));
        let before = SystemTime::now() - Duration::from_secs(1);
        stream.shared.write().unwrap().last_access = before;
        let appender = stream.appender.lock().await;
        let waiting_store = store.clone();
        let waiting =
            tokio::spawn(
                async move { handle(waiting_store, put("stream", Some(3_600), b"")).await },
            );
        tokio::task::yield_now().await;
        stream.fence_while_holding_appender(&appender);
        drop(appender);

        assert_eq!(
            timeout(Duration::from_secs(5), waiting)
                .await
                .unwrap()
                .unwrap()
                .status,
            503
        );
        assert_eq!(stream.shared.read().unwrap().last_access, before);
        assert!(!stream.meta_dirty.load(Ordering::Acquire));
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod append_fence_tests {
    use super::*;
    use crate::retirement::{RetirementConfig, TerminalCleanupCompletion};
    use crate::store::{
        CreateResult, ExplicitRetirementResult, InflightAppendGuard, ProducerState, Store,
        StreamConfig,
    };
    use crate::tier::TierConfig;
    use crate::wal::walset::WalSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn directory(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ds-append-fence-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config(ttl_seconds: Option<u64>) -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn post(path: &str, body: &'static [u8]) -> Req {
        Req {
            method: Method::Post,
            path: path.into(),
            query: None,
            headers: vec![("content-type".into(), "application/octet-stream".into())],
            body: Bytes::from_static(body),
        }
    }

    fn close(path: &str) -> Req {
        Req {
            method: Method::Post,
            path: path.into(),
            query: None,
            headers: vec![(H_CLOSED.into(), "true".into())],
            body: Bytes::new(),
        }
    }

    async fn wait_fenced(state: &StreamState) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.fenced.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retirement must fence the stream");
    }

    async fn wait_removed(state: &StreamState) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.file_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded cleanup must remove the stream");
    }

    async fn shutdown(store: &Store) {
        if let Some(executor) = store.retirement_executor() {
            executor.shutdown().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_fence_admission_rejects_fenced_stream() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("admission");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        let state = match store
            .create("append-fenced", config(None), None, 0)
            .unwrap()
        {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        let appender = state.appender.lock().await;
        state.fence_while_holding_appender(&appender);
        drop(appender);

        assert_eq!(
            handle(store.clone(), post("append-fenced", b"x"))
                .await
                .status,
            404
        );
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 0);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_fence_midflight_append_skips_publication_and_success() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("midflight-append");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        let state = match store
            .create("append-midflight", config(None), None, 0)
            .unwrap()
        {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        let pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::AppendPostDurablePreVisible,
            &state,
        );
        let task_store = store.clone();
        let task =
            tokio::spawn(async move { handle(task_store, post("append-midflight", b"x")).await });

        pause.wait_until_held().await;
        let appender = state.appender.lock().await;
        state.fence_while_holding_appender(&appender);
        drop(appender);
        pause.release();

        assert_eq!(task.await.unwrap().status, 404);
        assert_eq!(state.tail().bytes, 0);
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 0);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_before_wal_wait_cannot_publish_or_unlink_across_an_expiry_fence() {
        let _durability = test_support::DurabilityGuard::wal();
        let directory = directory("before-wal-expiry-fence");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        let wal = WalSet::open(&directory, Some(1), 1).unwrap();
        assert!(store.wal.set(wal.clone()).is_ok());
        wal.spawn_committers();
        let executor = store.init_retirement_executor().unwrap().clone();
        let state = match store
            .create("append-before-wal", config(Some(1)), None, 0)
            .unwrap()
        {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };

        let append_pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::AppendAfterAppenderDropBeforeWalWait,
            &state,
        );
        let append_store = store.clone();
        let append =
            tokio::spawn(
                async move { handle(append_store, post("append-before-wal", b"x")).await },
            );
        append_pause.wait_until_held().await;
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 1);
        // The append won live admission. Make this exact incarnation due only
        // after it has released the appender for its durability wait.
        state.shared.write().unwrap().last_access = UNIX_EPOCH;

        let fence_pause = crate::test_cut_points::pause(
            crate::test_cut_points::CutPoint::FenceAfterAppenderTransition,
            &state,
        );
        let retire_store = store.clone();
        let retire_stream = state.clone();
        let retire = tokio::spawn(async move { retire_store.retire_expiry(retire_stream).await });
        fence_pause.wait_until_held().await;

        assert!(state.fenced.load(Ordering::Acquire));
        assert!(
            state.file_path.exists(),
            "cleanup cannot unlink before append resolves"
        );
        assert!(store
            .registered_stream("append-before-wal")
            .is_some_and(|current| Arc::ptr_eq(&current, &state)));
        assert!(store
            .inventory_page(None, None, 10)
            .unwrap()
            .1
            .iter()
            .any(|entry| entry.path == "append-before-wal"));
        assert_eq!(executor.snapshot().total_jobs, 1);

        append_pause.release();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), append)
                .await
                .expect("fenced append must resolve")
                .expect("append task should not panic")
                .status,
            404,
            "a pre-durability append never returns a successful publication after fencing"
        );
        assert_eq!(state.tail().bytes, 0);
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 0);
        assert!(
            state.file_path.exists(),
            "the blocked logical transition cannot unlink after a rejected append"
        );

        fence_pause.release();

        let ticket = match tokio::time::timeout(Duration::from_secs(5), retire)
            .await
            .expect("retirement must continue after the append guard drains")
            .expect("retirement task should not panic")
        {
            ExplicitRetirementResult::Owner(ticket) => ticket,
            _ => panic!("the expiry owner must keep its exact ticket"),
        };
        assert!(matches!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        assert!(store.registered_stream("append-before-wal").is_none());
        assert!(!state.file_path.exists());
        assert_eq!(executor.snapshot().total_jobs, 0);
        shutdown(&store).await;
        wal.stop_committers();
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_fence_stage_failure_rolls_back_ttl_and_releases_guard() {
        let _durability = test_support::DurabilityGuard::wal();
        let directory = directory("stage-failure");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        let wal = WalSet::open(&directory, Some(1), 1).unwrap();
        assert!(store.wal.set(wal.clone()).is_ok());
        let state = match store
            .create("ttl-rollback", config(Some(3_600)), None, 0)
            .unwrap()
        {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        // Keep this TTL baseline far from expiry: this test reaches the WAL
        // stage-failure rollback, not the independently-tested lazy-expiry path.
        let original_access = SystemTime::now();
        state.shared.write().unwrap().last_access = original_access;
        wal.shard_for(state.id).fail_next_write();

        let request = Req {
            method: Method::Post,
            path: "ttl-rollback".into(),
            query: None,
            headers: vec![
                ("content-type".into(), "application/octet-stream".into()),
                (H_SEQ.into(), "7".into()),
                (H_PRODUCER_ID.into(), "producer".into()),
                (H_PRODUCER_EPOCH.into(), "0".into()),
                (H_PRODUCER_SEQ.into(), "0".into()),
            ],
            body: Bytes::from_static(b"x"),
        };
        assert_eq!(handle(store.clone(), request).await.status, 500);
        let shared = state.shared.read().unwrap();
        assert_eq!(shared.last_access, original_access);
        assert!(shared.producers.is_empty());
        assert_eq!(shared.last_seq_header, None);
        drop(shared);
        assert!(state.appender.try_lock().is_ok());
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 0);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_expiry_body_retires_without_mutation() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("expired-body");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        store.init_retirement_executor().unwrap();
        let state = match store.create("expired", config(Some(1)), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        state.shared.write().unwrap().last_access = UNIX_EPOCH;

        assert_eq!(
            handle(store.clone(), post("expired", b"x")).await.status,
            404
        );
        {
            let shared = state.shared.read().unwrap();
            assert_eq!(shared.last_access, UNIX_EPOCH);
            assert_eq!(shared.tail, 0);
            assert!(shared.producers.is_empty());
            assert!(!shared.closed);
        }
        assert!(!state.meta_dirty.load(Ordering::Acquire));
        assert!(state.fenced.load(Ordering::Acquire));
        wait_removed(&state).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_expiry_close_only_does_not_touch_or_close() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("expired-close");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        store.init_retirement_executor().unwrap();
        let state = match store.create("expired", config(Some(1)), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        state.shared.write().unwrap().last_access = UNIX_EPOCH;

        assert_eq!(handle(store.clone(), close("expired")).await.status, 404);
        {
            let shared = state.shared.read().unwrap();
            assert_eq!(shared.last_access, UNIX_EPOCH);
            assert!(!shared.closed);
            assert!(!shared.closed_durable);
        }
        assert!(!state.meta_dirty.load(Ordering::Acquire));
        wait_removed(&state).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_expiry_precedes_duplicate_and_idempotent_close_success() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("expired-idempotency");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        store.init_retirement_executor().unwrap();
        let duplicate = match store.create("duplicate", config(Some(1)), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        {
            let mut shared = duplicate.shared.write().unwrap();
            shared.last_access = UNIX_EPOCH;
            shared.producers.insert(
                "producer".into(),
                ProducerState {
                    epoch: 0,
                    last_seq: 7,
                },
            );
        }
        let duplicate_request = Req {
            method: Method::Post,
            path: "duplicate".into(),
            query: None,
            headers: vec![
                ("content-type".into(), "application/octet-stream".into()),
                (H_PRODUCER_ID.into(), "producer".into()),
                (H_PRODUCER_EPOCH.into(), "0".into()),
                (H_PRODUCER_SEQ.into(), "7".into()),
            ],
            body: Bytes::from_static(b"x"),
        };
        assert_eq!(handle(store.clone(), duplicate_request).await.status, 404);

        let closed = match store.create("closed", config(Some(1)), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        {
            let mut shared = closed.shared.write().unwrap();
            shared.last_access = UNIX_EPOCH;
            shared.closed = true;
            shared.closed_durable = true;
        }
        assert_eq!(handle(store.clone(), close("closed")).await.status, 404);
        wait_removed(&duplicate).await;
        wait_removed(&closed).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_expiry_queue_full_has_no_direct_fallback() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("expired-queue-full");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        store
            .init_retirement_executor_for_test(RetirementConfig {
                queue_capacity: 1,
                ..RetirementConfig::default()
            })
            .unwrap();
        let first = match store.create("first", config(Some(1)), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        let second = match store.create("second", config(Some(1)), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        first.shared.write().unwrap().last_access = UNIX_EPOCH;
        second.shared.write().unwrap().last_access = UNIX_EPOCH;
        let appender = first.appender.lock().await;
        let guard = InflightAppendGuard::begin(&first, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner = tokio::spawn(async move { handle(owner_store, post("first", b"x")).await });
        wait_fenced(&first).await;

        assert_eq!(
            handle(store.clone(), post("second", b"x")).await.status,
            404
        );
        assert!(!second.fenced.load(Ordering::Acquire));
        assert!(second.file_path.exists());
        drop(guard);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .status,
            404
        );
        wait_removed(&first).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_liveness_is_decided_when_the_appender_lock_is_acquired() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("expiry-at-lock");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        store.init_retirement_executor().unwrap();
        let state = match store.create("stream", config(Some(1)), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        let appender = state.appender.lock().await;
        let waiting_store = store.clone();
        let waiting =
            tokio::spawn(async move { handle(waiting_store, post("stream", b"x")).await });
        tokio::task::yield_now().await;
        state.shared.write().unwrap().last_access = UNIX_EPOCH;
        drop(appender);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .unwrap()
                .unwrap()
                .status,
            404
        );
        assert_eq!(state.tail().bytes, 0);
        wait_removed(&state).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_liveness_loses_to_a_fence_while_waiting_for_the_appender_lock() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("fence-at-lock");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        let state = match store.create("stream", config(None), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        let appender = state.appender.lock().await;
        let waiting_store = store.clone();
        let waiting =
            tokio::spawn(async move { handle(waiting_store, post("stream", b"x")).await });
        tokio::task::yield_now().await;
        state.fence_while_holding_appender(&appender);
        drop(appender);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .unwrap()
                .unwrap()
                .status,
            404
        );
        assert_eq!(state.tail().bytes, 0);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expiry_retirement_rechecks_the_deadline_before_fencing() {
        let _durability = test_support::DurabilityGuard::memory();
        let directory = directory("expiry-recheck");
        let store =
            Arc::new(Store::new_with_tier(directory.clone(), TierConfig::default()).unwrap());
        store.init_retirement_executor().unwrap();
        let state = match store
            .create("stream", config(Some(3_600)), None, 0)
            .unwrap()
        {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        state.shared.write().unwrap().last_access = UNIX_EPOCH;
        let appender = state.appender.lock().await;
        let retiring_store = store.clone();
        let retiring_state = state.clone();
        let retiring =
            tokio::spawn(async move { retiring_store.retire_expiry(retiring_state).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.retirement_state().is_clean() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expiry admission must reserve its exact ticket");
        state.shared.write().unwrap().last_access = SystemTime::now();
        drop(appender);

        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), retiring)
                .await
                .unwrap()
                .unwrap(),
            ExplicitRetirementResult::Cancelled(_)
        ));
        assert!(!state.fenced.load(Ordering::Acquire));
        assert!(Arc::ptr_eq(
            &store.registered_stream("stream").unwrap(),
            &state
        ));

        let ticket = match store.retire_explicit(state.clone()).await {
            ExplicitRetirementResult::Owner(ticket) => ticket,
            _ => panic!("explicit retirement must remain unconditional"),
        };
        assert!(matches!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        wait_removed(&state).await;
        shutdown(&store).await;
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod admin_inventory_tests {
    use super::*;
    use crate::api::Body;
    use crate::store::{CreateResult, Store, StreamConfig};
    use crate::store_manifest::StoreManifestV1;
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

    fn admin() -> Arc<crate::admin_readiness::AdminReadiness> {
        Arc::new(crate::admin_readiness::AdminReadiness::new(
            StoreManifestV1 {
                store_id: "test-store".into(),
                store_generation: "test-generation".into(),
                protocol_version: 1,
                layout_version: 1,
                durability_mode: "memory".into(),
                wal_shard_count: 0,
                stream_lane_count: 1,
                filesystem_uuid: "test-filesystem".into(),
                creation_time: "1970-01-01T00:00:00Z".into(),
            },
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            0,
            0,
        ))
    }

    fn admin_request(method: Method, path: &str) -> Req {
        Req {
            method,
            path: path.into(),
            query: None,
            headers: vec![],
            body: bytes::Bytes::new(),
        }
    }

    #[tokio::test]
    async fn expiry_admin_route_is_read_only_versioned_and_hidden_without_admin_context() {
        let dir = std::env::temp_dir().join(format!("ds-admin-expiry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let response = handle_with_admin(
            Arc::clone(&store),
            admin_request(Method::Get, "/_admin/expiry"),
            Some(admin()),
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| *name == "content-type" && value == "application/json"));
        let Body::Full(body) = response.body else {
            panic!("expiry response must be bounded JSON")
        };
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["contract_version"], "durable-streams-expiry-status-v1");
        assert!(body["scanner"].is_null());
        assert!(body["retirement"].is_null());

        assert_eq!(
            handle_with_admin(
                Arc::clone(&store),
                admin_request(Method::Post, "/_admin/expiry"),
                Some(admin()),
            )
            .await
            .status,
            405
        );
        assert_eq!(
            handle_with_admin(
                Arc::clone(&store),
                admin_request(Method::Get, "/_admin/not-a-route"),
                Some(admin()),
            )
            .await
            .status,
            404
        );
        assert_eq!(
            handle(
                Arc::clone(&store),
                admin_request(Method::Get, "/_admin/expiry")
            )
            .await
            .status,
            404
        );
        assert_eq!(
            handle_with_admin(
                Arc::clone(&store),
                admin_request(Method::Get, "/_admin%2Fexpiry"),
                Some(admin()),
            )
            .await
            .status,
            400
        );
        let _ = std::fs::remove_dir_all(&dir);
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
                headers: vec![("stream-closed".into(), "true".into())],
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
}
