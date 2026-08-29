// Stream store: per-stream state, contiguous wire-byte data files, coalesced fsync.
//
// On-disk layout: the data file contains exactly the wire bytes of the stream
// payload, contiguously.
//   - binary streams: raw payload bytes as POSTed
//   - JSON streams:   each message followed by a `,` separator
// A catch-up read is then a literal byte range of the file (JSON responses
// wrap the range as `[` + range-minus-trailing-comma + `]`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::{watch, Mutex as AsyncMutex, Notify};

pub const MAX_SAFE_INT: u64 = (1u64 << 53) - 1;
const CREATE_PATH_LOCK_STRIPES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tail {
    pub bytes: u64,
    pub closed: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProducerState {
    pub epoch: u64,
    pub last_seq: u64,
}

#[derive(Clone, Debug)]
pub struct StreamConfig {
    pub content_type: String,
    pub ttl_seconds: Option<u64>,
    pub expires_at: Option<SystemTime>,
    pub expires_at_raw: Option<String>,
    pub create_closed: bool,
    /// Fork identity (requested values, for idempotent re-PUT comparison).
    pub forked_from: Option<String>,
    pub fork_offset_raw: Option<String>,
    pub fork_sub_offset: Option<u64>,
}

pub struct Shared {
    /// Writer-facing logical tail (file_base + bytes written to this stream's own
    /// file). Advanced under the appender lock the instant bytes hit the page
    /// cache, so it can be AHEAD of what is durable. NOT what readers observe —
    /// see `durable_tail`.
    pub tail: u64,
    /// Reader-observable tail: advanced only AFTER the appended bytes are durable
    /// (in `wal` mode, after the WAL `fdatasync`; in `memory` mode, immediately —
    /// the page-cache write IS the ack). `tail()` reports this so a live/catch-up
    /// reader never observes (and acts on) bytes a crash could roll back
    /// (PROTOCOL.md §4.1) — the same durability-before-visibility ordering the
    /// close path applies via `closed_durable`. On recovery it equals the
    /// reconciled durable tail (durable by definition).
    pub durable_tail: u64,
    /// Logical offset of the live data file's first byte. Equals `base_offset`
    /// until the first compaction, then advances to the sealed watermark as the
    /// redundant sealed prefix is reclaimed. Live-region reads map
    /// `file_pos = logical - file_base`. Distinct from `base_offset`, the
    /// immutable fork point. Invariant: base_offset ≤ file_base ≤ sealed_offset ≤ tail.
    pub file_base: u64,
    /// Shared handle to the live data file for lock-free positioned reads. Held
    /// here (not on `StreamState`) so compaction can swap it together with
    /// `file_base` under one `shared.write()`, giving concurrent readers a
    /// consistent (file, file_base) pair.
    pub file: Arc<File>,
    /// Writer-facing close intent: set under the appender lock the instant a
    /// close is accepted (so subsequent appends are rejected) and persisted to
    /// the sidecar. NOT what readers observe — see `closed_durable`.
    pub closed: bool,
    /// Reader-observable EOF: set only AFTER the closure is durable (under `strict`,
    /// the data fsync + meta fsync; under `fast`, the meta fsync — the data fsync
    /// is skipped). `tail()` reports this so a reader never observes EOF for a
    /// closure a crash could roll back (PROTOCOL.md §4.1). On recovery it equals the
    /// persisted `closed` (durable by definition). Caveat (fast): the *closedness*
    /// never rolls back, but the closed *position* can shrink on an OS/power crash
    /// (the un-synced tail is lost; recovered `tail` = on-disk size). The full
    /// strict-only position-monotonicity guarantee holds only under `strict`.
    pub closed_durable: bool,
    /// Producer that closed the stream (producer_id, epoch, seq), for idempotent re-close.
    pub closed_by: Option<(String, u64, u64)>,
    pub producers: HashMap<String, ProducerState>,
    pub last_seq_header: Option<String>,
    pub last_access: SystemTime,
    /// Number of live forks reading through this stream.
    pub ref_count: u32,
    /// Deleted while forks still reference it: direct ops 410, path blocked.
    pub soft_deleted: bool,
}

pub struct Appender {
    pub file: Arc<File>,
    pub written: u64,
}

/// macOS uses fcntl(F_FULLFSYNC) for a true flush-to-platter (power-loss
/// durable), accepting slower fsyncs in macOS dev; the no-loss guarantee holds
/// on every platform. On Linux use fdatasync.
///
/// Returns the fsync result: a failure (e.g. EIO writeback error) MUST be
/// surfaced to the caller so an append is never acked as durable when the data
/// did not reach stable storage.
/// BENCH-ONLY: whether `DS_UNSAFE_FAST_FSYNC` requests plain `fsync` over
/// `F_FULLFSYNC` on macOS (see [`barrier_fsync`]). Read once and cached — the env
/// is fixed for the process lifetime.
#[cfg(target_os = "macos")]
fn fast_fsync_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("DS_UNSAFE_FAST_FSYNC").is_some())
}

pub(crate) fn barrier_fsync(file: &File) -> std::io::Result<()> {
    let fd = file.as_raw_fd();
    #[cfg(target_os = "macos")]
    unsafe {
        // BENCH-ONLY escape hatch (NOT for production durability): when
        // `DS_UNSAFE_FAST_FSYNC` is set, use a plain `fsync` instead of
        // `F_FULLFSYNC`. On macOS `F_FULLFSYNC` forces a true drive-cache barrier
        // (~tens of ms even on a RAM disk), which dominates the commit path and
        // masks the per-shard LOCK contention this build is meant to study. Plain
        // `fsync` on a RAM disk is ~free, reproducing the cheap-fsync (Linux +
        // NVMe) regime where the lock is the bottleneck. Never set this where data
        // must survive power loss.
        if fast_fsync_enabled() {
            return if libc::fsync(fd) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            };
        }
        // Force a true flush to platter; fall back to a plain fsync. Only error
        // if the final fallback also fails.
        if libc::fcntl(fd, libc::F_FULLFSYNC) == 0 {
            return Ok(());
        }
        // Preserve the F_FULLFSYNC cause before falling back; on double failure the
        // fallback fsync's errno alone would mislead durability diagnostics.
        let fullfsync_err = std::io::Error::last_os_error();
        if libc::fsync(fd) == 0 {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "F_FULLFSYNC failed ({fullfsync_err}); fallback fsync also failed ({})",
            std::io::Error::last_os_error()
        )))
    }
    #[cfg(not(target_os = "macos"))]
    unsafe {
        if libc::fdatasync(fd) == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

/// A single filesystem-wide durability barrier (Linux `syncfs`). Flushes ALL dirty
/// data+metadata on the filesystem that `file` lives on — used by the checkpoint's
/// `--wal-checkpoint-syncfs` path to make every touched per-stream file durable with
/// ONE syscall instead of `O(N_touched)` `fdatasync`s (cardinality-cliff #1). `file`
/// can be any open fd on the target fs (the checkpoint passes a touched stream file).
/// Linux-only; the caller gates on `cfg!(target_os = "linux")`, so the non-Linux stub
/// (which errors) is never reached in practice — it exists only so the crate compiles
/// on macOS.
#[cfg(target_os = "linux")]
pub(crate) fn syncfs_barrier(file: &File) -> std::io::Result<()> {
    // SAFETY: `fd` is a valid open descriptor for the lifetime of `file`.
    if unsafe { libc::syncfs(file.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn syncfs_barrier(_file: &File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "syncfs is Linux-only",
    ))
}

/// Stream-lane count (`--stream-lanes`, default 1 = the flat `streams/` layout).
/// With N > 1, stream data files are hashed across `streams/<0..N>/` subdirs so
/// each lane can be mounted on its OWN device: the checkpoint's dirty-file
/// writeback (the ~1M-stream wall — one `syncfs` measured at 60–74 s when every
/// stream shared one device, wal-1m-diag 2026-07-13) spreads over N devices and
/// runs N barriers in parallel, and no single ext4 directory holds every stream.
/// Must be set BEFORE `Store::open` and match the on-disk layout across restarts
/// (same N or files won't be found — a layout choice, not a runtime tunable).
static STREAM_LANES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
pub fn set_stream_lanes(n: usize) {
    STREAM_LANES.store(n.max(1), Ordering::Relaxed);
}
pub fn stream_lanes() -> usize {
    STREAM_LANES.load(Ordering::Relaxed)
}

/// Stable lane for a stream data-file name (FNV-1a; the fname embeds the stream
/// id, so this is fixed for the stream's lifetime and recomputable anywhere).
fn lane_of(fname: &str) -> usize {
    let lanes = stream_lanes();
    if lanes <= 1 {
        return 0;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in fname.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    (h % lanes as u64) as usize
}

/// Directory of lane `lane`: the flat `streams/` when lanes == 1 (byte-identical
/// to the historical layout), else `streams/<lane>/`.
fn lane_dir(data_dir: &std::path::Path, lane: usize) -> PathBuf {
    let root = data_dir.join("streams");
    if stream_lanes() <= 1 {
        root
    } else {
        root.join(lane.to_string())
    }
}

/// Open directory fds, one per stream lane, registered at `Store::open` — the
/// checkpoint's syncfs must barrier EVERY lane's filesystem (touched files can
/// live on any lane), and a dir fd is a valid syncfs target. Replaced (not
/// appended) per open so tests that build many stores target the latest layout.
static LANE_SYNC_FDS: StdMutex<Option<Arc<Vec<File>>>> = StdMutex::new(None);

/// Checkpoint durability barrier across all stream lanes: one `syncfs` per lane,
/// parallelized (each is a full device writeback and the lanes are independent
/// devices in the intended deployment). Falls back to a single barrier on
/// `fallback`'s fs when no lane registry exists (e.g. shard-only unit tests).
pub(crate) fn syncfs_stream_lanes(fallback: &File) -> std::io::Result<()> {
    let fds = LANE_SYNC_FDS.lock().unwrap().clone();
    match fds {
        Some(fds) if !fds.is_empty() => {
            if fds.len() == 1 {
                return syncfs_barrier(&fds[0]);
            }
            std::thread::scope(|s| {
                let handles: Vec<_> = fds
                    .iter()
                    .map(|f| s.spawn(move || syncfs_barrier(f)))
                    .collect();
                let mut first_err = None;
                for h in handles {
                    if let Err(e) = h
                        .join()
                        .unwrap_or_else(|_| Err(std::io::Error::other("syncfs thread panicked")))
                    {
                        first_err.get_or_insert(e);
                    }
                }
                match first_err {
                    None => Ok(()),
                    Some(e) => Err(e),
                }
            })
        }
        _ => syncfs_barrier(fallback),
    }
}

pub struct StreamState {
    pub id: u64,
    pub path: String,
    pub config: StreamConfig,
    pub is_json: bool,
    pub file_path: PathBuf,
    /// Logical offset where this stream's own file starts (fork point; 0 for roots).
    /// Immutable for the stream's lifetime; offsets below it route to `parent`.
    /// The live data file's *physical* start is `Shared::file_base`, which may
    /// advance past `base_offset` as compaction reclaims the sealed prefix.
    pub base_offset: u64,
    /// Fork source: ranges below base_offset are read through this chain.
    pub parent: Option<Arc<StreamState>>,
    pub appender: AsyncMutex<Appender>,
    pub shared: RwLock<Shared>,
    pub tail_tx: watch::Sender<Tail>,
    /// Retirement fence. Once set, no new append guard or request-time touch may
    /// succeed. This is transient; recovery reconstructs expiry from the sidecar.
    fenced: AtomicBool,
    /// Appends that have left `appender` but have not yet completed their full
    /// durability/publication/notification/response path.
    inflight_appends: AtomicUsize,
    inflight_appends_zero: Notify,
    /// Dedupe latch used by the bounded runtime retirement queue.
    retirement_queued: AtomicBool,
    /// Set after physical hard unlink when WAL bookkeeping begins forgetting
    /// this stream. Checkpoint/dirty registration uses it to avoid restoring a
    /// retired stream to the WAL tail proof after the forget operation starts.
    wal_forgotten: AtomicBool,
    /// Ensures retrying a partially completed hard retirement releases its
    /// parent reference at most once.
    parent_released: AtomicBool,
    /// Sticky deletion wake: new subscribers also observe an already-fired wake.
    deleted_tx: watch::Sender<bool>,
    /// The sidecar's persisted `durable_tail` as read at BOOT (None for sidecars
    /// written by older servers). Consumed once by WAL recovery as this stream's
    /// truncation-proof seed; never updated afterwards (the live value lives in
    /// `Shared.durable_tail` and is re-captured on every meta write).
    pub boot_meta_durable_tail: Option<u64>,
    /// True while a debounced meta flush is pending.
    pub meta_dirty: AtomicBool,
    /// **Lock-free WAL dirty-set marker** (Tier-1a). The shard's checkpoint epoch
    /// at which this stream was last registered into its shard's dirty set. The
    /// hot append path compares this against the shard's current epoch: equal ⇒
    /// already registered this interval (no lock, no push); not-equal ⇒ CAS it to
    /// the current epoch and, on the winning transition only, push this stream's
    /// `Arc<StreamState>` into the shard's dirty collection. Initialised to `0`
    /// (the shard's epoch starts at `1`), so the first append after creation always
    /// registers. See `Shard::register_dirty`.
    pub dirty_epoch: AtomicU64,
    /// Serializes sidecar writes for this stream. Concurrent writers (append
    /// flush, close, tiering offload flip, delete) otherwise race on the shared
    /// `.meta.tmp` file and can reorder their renames, letting a stale non-durable
    /// flush clobber a durable manifest flip. Held across capture+write+rename so
    /// the last writer persists the freshest captured state.
    pub meta_lock: StdMutex<()>,
    /// Most recently appended wire chunk, kept resident so caught-up live
    /// readers (SSE / long-poll) and immediate catch-up reads are served from
    /// memory — one read+encode shared across all subscribers — instead of a
    /// per-subscriber file read. `(start, bytes)` covers `[start, start+len)`.
    /// Only populated for chunks up to the tail-cache cap (large appends fall back
    /// to file reads / sendfile). See set_last_chunk / tail_chunk_slice.
    /// `RwLock` (not `Mutex`) so concurrent readers fanning out over the same
    /// just-appended tail share it without serializing on a lock.
    pub last_chunk: RwLock<Option<(u64, bytes::Bytes)>>,
    /// Hot/cold tiering state: the per-stream sealing manifest. Always present;
    /// empty and inert unless tiering is enabled (`--tier`). See tier.rs.
    pub tier: crate::tier::TierState,
    /// Remote tier handle, cloned from the Store. None when tiering is off, so
    /// the read path stays a pure local-fd path in the default build.
    pub blobstore: Option<crate::blobstore::SharedBlobStore>,
    /// In-flight live-file compaction intent. `Some` only during a compaction
    /// pass (between the intent meta-write and its clear). Persisted by
    /// `Meta::capture` so a crash mid-compaction is recoverable. See tier.rs.
    pub compaction: StdMutex<Option<PendingCompaction>>,
    /// Reactor-served SSE subscribers of this stream (Linux). `None` while the
    /// stream has none — the common case — so idle streams cost only the lock +
    /// a null pointer; the list (and its allocation) exist only while subscribers
    /// are attached. See sse_reactor.rs.
    #[cfg(target_os = "linux")]
    pub sse_subs: StdMutex<Option<Box<StreamSubs>>>,
}

/// RAII coverage for the complete append acknowledgment path. The handler must
/// create this while it still holds `StreamState::appender`, and keep it alive
/// through the final publish/notification/response decision.
pub struct AppendGuard {
    stream: Arc<StreamState>,
}

impl AppendGuard {
    /// Recheck after WAL durability and immediately before visibility or 2xx.
    pub fn may_publish(&self) -> bool {
        !self.stream.fenced.load(Ordering::Acquire)
    }
}

impl Drop for AppendGuard {
    fn drop(&mut self) {
        if self.stream.inflight_appends.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.stream.inflight_appends_zero.notify_waiters();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamAccessError {
    Gone,
    Expired,
}

#[derive(Clone)]
pub struct ExpiryCandidate {
    stream_id: u64,
    stream: Arc<StreamState>,
}

impl ExpiryCandidate {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn stream(&self) -> Arc<StreamState> {
        Arc::clone(&self.stream)
    }

    pub fn try_mark_queued(&self) -> bool {
        self.stream
            .retirement_queued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn clear_queued(&self) {
        self.stream
            .retirement_queued
            .store(false, Ordering::Release);
    }
}

#[derive(Default)]
pub struct ExpiryScanCursor {
    after: Option<u64>,
}

impl ExpiryScanCursor {
    pub fn after(&self) -> Option<u64> {
        self.after
    }
}

pub struct ExpiryScanPage {
    pub checked: usize,
    pub due: Vec<ExpiryCandidate>,
    pub completed_pass: bool,
    /// Oldest deadline found due in this bounded page. Runtime telemetry derives
    /// scheduling lag from this without adding an unbounded global walk.
    pub oldest_due_deadline: Option<SystemTime>,
}

pub enum StreamLookup {
    Missing,
    Gone(#[allow(dead_code)] Arc<StreamState>),
    Expired(ExpiryCandidate),
    Live(Arc<StreamState>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareRetirement {
    Ready,
    Renewed,
    Stale,
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementDurability {
    Expiry,
    Explicit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementOutcome {
    SoftDeleted,
    Reaped,
}

pub struct RetirementStep {
    pub outcome: RetirementOutcome,
    /// A zero-reference soft fork parent made eligible by this hard retirement.
    /// It is fenced but deliberately not queue-marked; the bounded runtime must
    /// admit and pace it as a distinct physical cleanup step.
    pub cascade: Option<ExpiryCandidate>,
    /// Data-file and sidecar bytes successfully unlinked by this step. Local
    /// tier segments are currently reclaimed asynchronously and are not included.
    pub reclaimed_local_bytes: u64,
}

struct PhysicalRetirementStep {
    outcome: RetirementOutcome,
    cascade: Option<ExpiryCandidate>,
    reclaimed_local_bytes: u64,
}

#[derive(Default)]
struct ExpiringStreams {
    by_id: BTreeMap<u64, Weak<StreamState>>,
}

/// Reactor subscriber list for one stream — populated only while subscribers are
/// attached (kept behind `Option<Box<…>>` so idle streams pay nothing).
#[cfg(target_os = "linux")]
pub struct StreamSubs {
    pub subs: Vec<SubHandle>,
    /// Wake-coalescing latch: set by `wake_stream` when it queues this stream's
    /// subscribers, cleared by the reactor BEFORE it reads the tail to flush
    /// (clear-then-read: a publish racing the flush either lands before the
    /// clear — its bytes are covered by the post-clear tail read — or after,
    /// and re-queues). Converts per-append wakes into one wake per stream per
    /// reactor cycle under load — the fan-out batching that wal mode gets for
    /// free from group commit, without which memory mode drowns the reactor in
    /// per-append eventfd signals (measured: delivery collapse past ~16k w/s).
    pub wake_pending: std::sync::atomic::AtomicBool,
}

/// Locates one reactor subscriber: which shard owns it, its slab key, and the
/// slot generation (so a stale wake for a freed/reused slot is ignored).
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub struct SubHandle {
    pub shard: u16,
    pub key: u32,
    pub gen: u32,
}

/// Crash-recovery intent for a live-file compaction in progress. While set, the
/// live data file is being swapped from `[old_file_base, tail)` to
/// `[new_file_base, tail)`; because compaction holds the appender lock end to
/// end, `tail` is frozen, so on boot the on-disk file ends at `tail` whichever
/// side of the rename the crash fell on. Recovery sets
/// `file_base = tail - file_size`, which resolves to the correct base for either
/// file. See `recover_one_inner`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct PendingCompaction {
    pub new_file_base: u64,
    pub tail: u64,
}

/// Default resident tail-chunk cap (bytes). macOS has **no `sendfile`** — reads
/// fall back to positioned `pread`, so the in-memory tail cache is the read
/// fast-path and is **ON by default** there (64 KiB). Linux serves reads
/// zero-copy via `sendfile`, so the cache is **OFF by default** (`0`); enable /
/// tune with `--tail-cache-bytes`.
#[cfg(target_os = "macos")]
pub const DEFAULT_TAIL_CACHE_BYTES: usize = 64 * 1024;
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_TAIL_CACHE_BYTES: usize = 0;

/// Resident tail-chunk cap in bytes (process-global; set once at startup from
/// `--tail-cache-bytes`). `0` disables the cache — every read resolves to the
/// file (`sendfile` / `pread`). Appends larger than the cap are not cached.
static TAIL_CACHE_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_TAIL_CACHE_BYTES);

/// Set the resident tail-cache cap (bytes). `0` disables the cache.
pub fn set_tail_cache_bytes(n: usize) {
    TAIL_CACHE_BYTES.store(n, Ordering::Relaxed);
}
/// Current resident tail-cache cap (bytes). `0` = disabled.
pub fn tail_cache_bytes() -> usize {
    TAIL_CACHE_BYTES.load(Ordering::Relaxed)
}

impl StreamState {
    fn has_expiration_policy(&self) -> bool {
        self.config.ttl_seconds.is_some() || self.config.expires_at.is_some()
    }

    /// Record the just-appended wire chunk as the resident tail. `start` is the
    /// logical offset where `bytes` begins. Chunks larger than the tail-cache cap
    /// (or any append when the cache is disabled) are not cached (the entry is
    /// cleared so a stale chunk is never served).
    pub fn set_last_chunk(&self, start: u64, bytes: bytes::Bytes) {
        let cap = tail_cache_bytes();
        let mut g = self.last_chunk.write().unwrap();
        *g = if cap > 0 && bytes.len() <= cap {
            Some((start, bytes))
        } else {
            None
        };
    }

    /// Return the resident bytes for `[want_start, want_end)` iff the cached
    /// tail chunk fully covers that range; otherwise None (caller reads the
    /// file). Cheap: `Bytes::slice` is a refcount bump, no copy.
    pub fn tail_chunk_slice(&self, want_start: u64, want_end: u64) -> Option<bytes::Bytes> {
        // Cache disabled (cap 0) → straight to the file path, no lock taken.
        if want_end <= want_start || tail_cache_bytes() == 0 {
            return None;
        }
        let g = self.last_chunk.read().unwrap();
        let (cstart, cbytes) = g.as_ref()?;
        let cend = cstart + cbytes.len() as u64;
        if *cstart <= want_start && want_end <= cend {
            let a = (want_start - cstart) as usize;
            let b = (want_end - cstart) as usize;
            Some(cbytes.slice(a..b))
        } else {
            None
        }
    }

    pub fn tail(&self) -> Tail {
        let s = self.shared.read().unwrap();
        Tail {
            // Readers observe bytes only once they are durable, and EOF only once
            // the closure is durable.
            bytes: s.durable_tail,
            closed: s.closed_durable,
        }
    }

    fn expiry_deadline_for(&self, last_access: SystemTime) -> Option<SystemTime> {
        if let Some(expires_at) = self.config.expires_at {
            return Some(expires_at);
        }
        self.config
            .ttl_seconds
            .and_then(|ttl| last_access.checked_add(Duration::from_secs(ttl)))
    }

    #[allow(dead_code)]
    pub fn expiry_deadline(&self) -> Option<SystemTime> {
        self.expiry_deadline_for(self.shared.read().unwrap().last_access)
    }

    fn is_expired_with(&self, shared: &Shared, now: SystemTime) -> bool {
        self.expiry_deadline_for(shared.last_access)
            .is_some_and(|deadline| now > deadline)
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.is_expired_with(&self.shared.read().unwrap(), now)
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(SystemTime::now())
    }

    /// Atomically validate request-time liveness and refresh a sliding TTL.
    /// The shared write guard also serializes this decision with retirement's
    /// final expiry recheck + fence.
    #[allow(dead_code)]
    pub fn touch_if_live_at(&self, now: SystemTime) -> bool {
        let mut shared = self.shared.write().unwrap();
        if self.fenced.load(Ordering::Acquire)
            || shared.soft_deleted
            || self.is_expired_with(&shared, now)
        {
            return false;
        }
        if self.config.ttl_seconds.is_some() {
            shared.last_access = now;
        }
        true
    }

    /// Begin full-path append accounting. Must be called while `appender` is
    /// held, after request validation and before releasing that mutex.
    pub fn begin_append_at(
        self: &Arc<Self>,
        now: SystemTime,
    ) -> Result<AppendGuard, StreamAccessError> {
        let shared = self.shared.read().unwrap();
        if shared.soft_deleted {
            return Err(StreamAccessError::Gone);
        }
        if self.fenced.load(Ordering::Acquire) || self.is_expired_with(&shared, now) {
            return Err(StreamAccessError::Expired);
        }
        self.inflight_appends.fetch_add(1, Ordering::AcqRel);
        Ok(AppendGuard {
            stream: Arc::clone(self),
        })
    }

    pub fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::Acquire)
    }

    pub fn mark_wal_forgotten(&self) {
        self.wal_forgotten.store(true, Ordering::Release);
    }

    pub fn is_wal_forgotten(&self) -> bool {
        self.wal_forgotten.load(Ordering::Acquire)
    }

    /// Mutate request-visible stream state only while it is live. The fence
    /// decision and mutation share retirement's `shared` lock, so neither a
    /// durable publication nor a last-access update can land after fencing.
    pub fn with_live_shared_mut<R>(
        &self,
        f: impl FnOnce(&mut Shared) -> R,
    ) -> Result<R, StreamAccessError> {
        let mut shared = self.shared.write().unwrap();
        if shared.soft_deleted {
            return Err(StreamAccessError::Gone);
        }
        if self.fenced.load(Ordering::Acquire) {
            return Err(StreamAccessError::Expired);
        }
        Ok(f(&mut shared))
    }

    /// Atomically advance the reader-visible durable tail if retirement has not
    /// fenced the stream. The caller publishes the returned exact tail to
    /// watches/inventory after releasing this lock.
    pub fn publish_durable_tail_if_live(
        &self,
        tail: u64,
    ) -> Result<Option<Tail>, StreamAccessError> {
        self.with_live_shared_mut(|shared| {
            if tail <= shared.durable_tail {
                return None;
            }
            shared.durable_tail = tail;
            Some(Tail {
                bytes: tail,
                closed: shared.closed_durable,
            })
        })
    }

    /// Atomically publish durable EOF if retirement has not fenced the stream.
    pub fn publish_durable_close_if_live(&self) -> Result<Tail, StreamAccessError> {
        self.with_live_shared_mut(|shared| {
            shared.closed_durable = true;
            Tail {
                bytes: shared.durable_tail,
                closed: true,
            }
        })
    }

    /// Atomically publish a body append and its durable close. Delaying both
    /// visibility transitions until close metadata commits prevents retirement
    /// from fencing between a visible body and EOF publication.
    pub fn publish_durable_tail_and_close_if_live(
        &self,
        tail: u64,
    ) -> Result<(Tail, bool), StreamAccessError> {
        self.with_live_shared_mut(|shared| {
            let advanced = tail > shared.durable_tail;
            if advanced {
                shared.durable_tail = tail;
            }
            shared.closed_durable = true;
            (
                Tail {
                    bytes: shared.durable_tail,
                    closed: true,
                },
                advanced,
            )
        })
    }

    pub fn subscribe_deleted(&self) -> watch::Receiver<bool> {
        self.deleted_tx.subscribe()
    }

    /// Publish the request-time fence transition after releasing `shared`.
    /// Deletion is sticky for future subscribers; the tail/reactor wakes end
    /// existing long-poll and SSE readers before paced cleanup is admitted.
    fn publish_retirement_fence_wake(&self) {
        let first = self.deleted_tx.send_if_modified(|deleted| {
            if *deleted {
                false
            } else {
                *deleted = true;
                true
            }
        });
        if !first {
            return;
        }
        let _ = self.tail_tx.send(self.tail());
        #[cfg(target_os = "linux")]
        crate::sse_reactor::wake_stream(self);
    }

    async fn wait_for_inflight_appends(&self) {
        loop {
            // Register before observing zero so the final guard transition
            // cannot be missed between the check and the await.
            let notified = self.inflight_appends_zero.notified();
            if self.inflight_appends.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    pub fn etag(&self, start: u64, end: u64, closed: bool) -> String {
        if closed {
            format!("\"{}:{}:{}:c\"", self.id, start, end)
        } else {
            format!("\"{}:{}:{}\"", self.id, start, end)
        }
    }
}

pub struct Store {
    pub streams: DashMap<String, Arc<StreamState>>,
    /// Serializes creation of the same logical path without retaining a
    /// DashMap shard guard across data/sidecar I/O. Lookups never take these
    /// locks; unrelated creates contend only when their path hashes collide.
    creation_stripes: [StdMutex<()>; CREATE_PATH_LOCK_STRIPES],
    pub data_dir: PathBuf,
    next_id: AtomicU64,
    /// Hot/cold tiering config (Off by default → fully inert).
    pub tier_config: crate::tier::TierConfig,
    /// Remote object-storage backend, present only when tiering is enabled.
    pub blobstore: Option<crate::blobstore::SharedBlobStore>,
    /// The sharded write-ahead log, present only under `--durability wal`. Empty
    /// for `strict`/`fast`, which keeps the WAL inert and those paths unchanged.
    ///
    /// A `OnceLock` (not a plain `Option`) so it can be attached **once**,
    /// post-construction, on the already-`Arc`-wrapped `Store`: `new_with_tier`
    /// runs the sidecar recover pass before the WAL is built, then main.rs builds
    /// the `WalSet`, runs WAL recovery, and `set`s it here — all before serving.
    /// The hot-path read (`store.wal.get()`) is lock-free.
    pub wal: std::sync::OnceLock<Arc<crate::wal::walset::WalSet>>,
    /// Streams with a pending non-durable sidecar flush (memory-mode appends,
    /// TTL read touches), drained in batch by the periodic meta sweeper
    /// (`sweep_meta_once`). The `meta_dirty` CAS in `mark_meta_dirty` keeps
    /// each stream in here at most once per sweep cycle (#4691).
    pub meta_sweep: StdMutex<Vec<Arc<StreamState>>>,
    pub subscriptions: Arc<crate::subscriptions::SubscriptionManager>,
    inventory: RwLock<InventoryProjection>,
    expiring: StdMutex<ExpiringStreams>,
    recovered_retirements: StdMutex<ExpiringStreams>,
    /// Sticky recovery quarantine summary. WAL recovery uses this to refuse a
    /// replay/reset that could otherwise discard records for a stream whose
    /// sidecar could not be decoded. Memory mode may still boot for operator
    /// repair, so this state remains queryable for the Store lifetime.
    quarantined_streams: AtomicBool,
    quarantined_stream_ids_complete: AtomicBool,
    quarantined_stream_ids: RwLock<HashSet<u64>>,
}

/// A read-only stream projection used by the bounded administrative inventory.
#[derive(Clone, Debug)]
pub struct InventoryEntry {
    stream_id: u64,
    pub path: String,
    pub closed: bool,
    pub deleted: bool,
    pub durable_bytes: u64,
}

struct InventoryProjection {
    generation: u64,
    entries: BTreeMap<String, InventoryEntry>,
}
#[derive(Debug)]
pub enum InventoryPageError {
    GenerationChanged,
}

pub enum CreateResult {
    Created(Arc<StreamState>),
    Exists(Arc<StreamState>),
    /// The old incarnation remains fenced in the registry. The caller must run
    /// prepare → subscription transition → finish, then retry creation once.
    Expired(ExpiryCandidate),
    /// The requested fork source became fenced, deleted, or expired while the
    /// child reservation was being established.
    SourceUnavailable,
    Conflict,
}

impl Store {
    pub fn has_quarantined_streams(&self) -> bool {
        self.quarantined_streams.load(Ordering::Acquire)
    }

    /// Whether every quarantined sidecar's data filename contained a valid
    /// stream id. `false` means callers cannot safely narrow a WAL preflight to
    /// the ids returned by [`Store::quarantined_stream_ids`].
    pub fn quarantined_stream_ids_complete(&self) -> bool {
        self.quarantined_stream_ids_complete.load(Ordering::Acquire)
    }

    pub fn quarantined_stream_ids(&self) -> Vec<u64> {
        let mut ids: Vec<_> = self
            .quarantined_stream_ids
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .copied()
            .collect();
        ids.sort_unstable();
        ids
    }

    fn record_quarantined_stream(&self, data_path: &std::path::Path) -> Option<u64> {
        self.quarantined_streams.store(true, Ordering::Release);
        let id = data_path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.rsplit_once('~'))
            .and_then(|(_, id)| id.parse::<u64>().ok())
            .filter(|id| *id <= MAX_SAFE_INT);
        match id {
            Some(id) => {
                self.quarantined_stream_ids
                    .write()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(id);
            }
            None => self
                .quarantined_stream_ids_complete
                .store(false, Ordering::Release),
        }
        id
    }

    fn evaluate_existing_create(
        &self,
        existing: Arc<StreamState>,
        requested: &StreamConfig,
        now: SystemTime,
    ) -> CreateResult {
        let mut shared = existing.shared.write().unwrap();
        if shared.soft_deleted {
            return CreateResult::Conflict;
        }
        if existing.fenced.load(Ordering::Acquire) || existing.is_expired_with(&shared, now) {
            existing.fenced.store(true, Ordering::Release);
            existing.meta_dirty.store(false, Ordering::Release);
            drop(shared);
            existing.publish_retirement_fence_wake();
            return CreateResult::Expired(self.candidate_for(&existing));
        }
        let matches = config_matches_with_closed(&existing, requested, shared.closed);
        if matches && existing.config.ttl_seconds.is_some() {
            shared.last_access = now;
        }
        drop(shared);
        if matches {
            CreateResult::Exists(existing)
        } else {
            CreateResult::Conflict
        }
    }

    fn publish_inventory(&self, st: &StreamState) {
        let s = st.shared.read().unwrap();
        let entry = InventoryEntry {
            stream_id: st.id,
            path: st.path.clone(),
            closed: s.closed_durable,
            deleted: s.soft_deleted,
            durable_bytes: s.durable_tail,
        };
        let mut inventory = self.inventory.write().unwrap();
        inventory.entries.insert(entry.path.clone(), entry);
        inventory.generation = inventory.generation.wrapping_add(1);
    }
    pub fn publish_inventory_tail(&self, st: &StreamState) {
        self.publish_inventory(st);
    }
    pub fn refresh_inventory(&self) {
        let mut entries = BTreeMap::new();
        for stream in self.streams.iter() {
            let stream = stream.value();
            let shared = stream.shared.read().unwrap();
            entries.insert(
                stream.path.clone(),
                InventoryEntry {
                    stream_id: stream.id,
                    path: stream.path.clone(),
                    closed: shared.closed_durable,
                    deleted: shared.soft_deleted,
                    durable_bytes: shared.durable_tail,
                },
            );
        }
        let mut inventory = self.inventory.write().unwrap();
        inventory.entries = entries;
        inventory.generation = inventory.generation.wrapping_add(1);
    }
    fn remove_inventory(&self, path: &str, expected_stream_id: u64) {
        let mut inventory = self.inventory.write().unwrap();
        let matches = inventory
            .entries
            .get(path)
            .is_some_and(|entry| entry.stream_id == expected_stream_id);
        if matches && inventory.entries.remove(path).is_some() {
            inventory.generation = inventory.generation.wrapping_add(1);
        }
    }
    pub fn inventory_page(
        &self,
        generation: Option<u64>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(u64, Vec<InventoryEntry>, bool), InventoryPageError> {
        let inventory = self.inventory.read().unwrap();
        if generation.is_some_and(|generation| generation != inventory.generation) {
            return Err(InventoryPageError::GenerationChanged);
        }
        let entries: Vec<_> = inventory
            .entries
            .range((
                match after {
                    Some(after) => std::ops::Bound::Excluded(after.to_owned()),
                    None => std::ops::Bound::Unbounded,
                },
                std::ops::Bound::Unbounded,
            ))
            .take(limit + 1)
            .map(|(_, entry)| entry.clone())
            .collect();
        let more = entries.len() > limit;
        Ok((
            inventory.generation,
            entries.into_iter().take(limit).collect(),
            more,
        ))
    }
    /// Build a Store with an explicit tiering configuration. When
    /// `tier.kind == Off` (the default) this is identical to `new`: no
    /// blobstore, no sealing, single contiguous file per stream.
    pub fn new_with_tier(
        data_dir: PathBuf,
        tier_config: crate::tier::TierConfig,
    ) -> std::io::Result<Self> {
        let streams_dir = data_dir.join("streams");
        std::fs::create_dir_all(&streams_dir)?;
        // Whether this store existed before THIS boot — captured before the
        // `.lanes` block below writes the marker on first initialization (the
        // lane-mount guard must not fire on a genuinely fresh store).
        let store_initialized = streams_dir.join(".lanes").exists();
        // Persist + validate the stream-lane count (mirrors the WAL shard count's
        // persisted-N contract): opening a laned layout with a different
        // `--stream-lanes` would make every existing stream silently invisible
        // (recovery walks the wrong dirs). Refuse loudly instead.
        {
            let marker = streams_dir.join(".lanes");
            match std::fs::read_to_string(&marker) {
                Ok(txt) => {
                    let on_disk: usize = txt.trim().parse().map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("corrupt stream-lane marker {}", marker.display()),
                        )
                    })?;
                    if on_disk != stream_lanes() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "--stream-lanes {} does not match this data dir's on-disk layout ({} lanes, recorded in {}). The lane count is a layout choice and must match across restarts.",
                                stream_lanes(),
                                on_disk,
                                marker.display()
                            ),
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Legacy pre-marker dirs are all lanes == 1: refuse enabling
                    // lanes over an existing flat layout (its files would vanish).
                    if stream_lanes() > 1
                        && std::fs::read_dir(&streams_dir)?
                            .flatten()
                            .any(|e| e.path().is_file())
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "--stream-lanes > 1 over an existing flat streams/ layout; this data dir was created with 1 lane",
                        ));
                    }
                    // Durable write (tmp + sync + rename + dir fsync): losing
                    // this marker while laned dirs full of data survive would
                    // let a later boot mis-read the layout.
                    let tmp = streams_dir.join(".lanes.tmp");
                    {
                        use std::io::Write;
                        let mut f = File::create(&tmp)?;
                        f.write_all(format!("{}\n", stream_lanes()).as_bytes())?;
                        f.sync_all()?;
                    }
                    std::fs::rename(&tmp, &marker)?;
                    fsync_parent_dir(&marker)?;
                }
                Err(e) => return Err(e),
            }
        }
        // Create every stream-lane dir and register their dir fds for the
        // checkpoint's per-lane syncfs barrier (see `syncfs_stream_lanes`).
        {
            let mut lane_fds = Vec::with_capacity(stream_lanes());
            for lane in 0..stream_lanes() {
                let d = lane_dir(&data_dir, lane);
                // MOUNT GUARD: each lane dir carries a `.lane` marker written at
                // first initialization. Lane dirs are mountpoints for independent
                // devices in the intended layout — if a lane's mount is absent at
                // boot, `create_dir_all` silently recreates an EMPTY dir on the
                // parent fs, every stream on that lane vanishes from recovery,
                // and the WAL reset then destroys their acked records. So: once
                // the store is initialized (the `.lanes` count marker exists), a
                // lane whose `.lane` marker is missing AND whose dir is empty is
                // treated as a missing mount and boot is refused. (A missing
                // marker with contents present = pre-marker layout: adopt it.)
                let marker = d.join(".lane");
                if store_initialized && !marker.exists() {
                    let has_contents = std::fs::read_dir(&d)
                        .map(|mut it| it.next().is_some())
                        .unwrap_or(false);
                    if !has_contents {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!(
                                "stream lane {lane} at {} is empty and unmarked on an \
                                 initialized store — its device mount is likely missing. \
                                 Refusing to boot: continuing would drop every stream on \
                                 this lane and the WAL reset would destroy their acked \
                                 records. Mount the lane device (or restore its data) and \
                                 restart.",
                                d.display()
                            ),
                        ));
                    }
                }
                std::fs::create_dir_all(&d)?;
                if !marker.exists() {
                    let mut f = File::create(&marker)?;
                    use std::io::Write;
                    f.write_all(lane.to_string().as_bytes())?;
                    f.sync_all()?;
                    fsync_parent_dir(&marker)?;
                }
                lane_fds.push(File::open(&d)?);
            }
            *LANE_SYNC_FDS.lock().unwrap() = Some(Arc::new(lane_fds));
        }
        // Stream data can be sensitive; keep the data dir owner-only (best-effort).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700));
        }
        // Intentional u128→u64 truncation: this is only an id seed, and it is
        // masked by `& MAX_SAFE_INT` below. Non-panicking on a pre-1970 clock
        // (unlike `.unwrap()`), matching the `unix_secs` helper's discipline.
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let blobstore = build_blobstore(&tier_config, &data_dir)?;
        let subscriptions = Arc::new(crate::subscriptions::SubscriptionManager::new(&data_dir)?);
        let store = Store {
            streams: DashMap::new(),
            creation_stripes: std::array::from_fn(|_| StdMutex::new(())),
            data_dir,
            next_id: AtomicU64::new(seed & MAX_SAFE_INT),
            tier_config,
            blobstore,
            wal: std::sync::OnceLock::new(),
            meta_sweep: StdMutex::new(Vec::new()),
            subscriptions,
            inventory: RwLock::new(InventoryProjection {
                generation: 0,
                entries: BTreeMap::new(),
            }),
            expiring: StdMutex::new(ExpiringStreams::default()),
            recovered_retirements: StdMutex::new(ExpiringStreams::default()),
            quarantined_streams: AtomicBool::new(false),
            quarantined_stream_ids_complete: AtomicBool::new(true),
            quarantined_stream_ids: RwLock::new(HashSet::new()),
        };
        store.recover(&streams_dir)?;
        Ok(store)
    }

    /// Directory holding staged sealed chunk files (separate from `streams/` so
    /// recovery's data-file scan never trips over them).
    pub fn segments_dir(&self) -> PathBuf {
        self.data_dir.join("segments")
    }

    /// Rebuild stream state from data files + metadata sidecars. The data file
    /// is the source of truth for content (tail = base_offset + file size, a
    /// property of the contiguous wire-byte layout); the sidecar provides
    /// everything else. Orphan files (crash between create and meta write) are
    /// discarded.
    fn recover(&self, streams_dir: &std::path::Path) -> std::io::Result<()> {
        let _ = streams_dir; // root; per-lane dirs derived below (lane 0 == root when lanes == 1)
        let mut metas: HashMap<String, (Meta, PathBuf)> = HashMap::new();
        let mut data_files: Vec<PathBuf> = Vec::new();
        let mut quarantined: Vec<PathBuf> = Vec::new();
        let mut max_id = 0u64;
        let mut entries: Vec<PathBuf> = Vec::new();
        for lane in 0..stream_lanes() {
            for entry in std::fs::read_dir(lane_dir(&self.data_dir, lane))? {
                entries.push(entry?.path());
            }
        }
        for p in entries {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == ".lanes" || name == ".lane" {
                // stream-lane layout / lane-mount markers, not stream data
                continue;
            }
            if name.ends_with(".meta.tmp") {
                let _ = std::fs::remove_file(&p);
            } else if name.ends_with(".compact.tmp") {
                // A compaction temp file. It belongs to its data file and is
                // handled by `recover_one_inner` (promoted when it holds the
                // durable residual for a pending intent, else removed there). Do
                // NOT treat it as an orphan data file — that would delete the
                // durable residual before recovery can promote it.
            } else if name.ends_with(".meta.corrupt") {
                // A prior boot deliberately parked an unreadable sidecar. Keep
                // recognizing that quarantine marker forever: otherwise the
                // next boot would classify both the marker and its paired data
                // as disposable orphans, and could also lower a soft fork
                // parent's refcount using an incomplete child graph.
                let data_path = PathBuf::from(
                    p.as_os_str()
                        .to_str()
                        .unwrap()
                        .trim_end_matches(".meta.corrupt"),
                );
                eprintln!(
                    "WARN: retaining quarantined stream sidecar {} \
                     (stream skipped this boot; paired data kept)",
                    p.display()
                );
                if let Some(id) = self.record_quarantined_stream(&data_path) {
                    max_id = max_id.max(id);
                }
                quarantined.push(data_path);
            } else if name.ends_with(".meta") {
                let data_path =
                    PathBuf::from(p.as_os_str().to_str().unwrap().trim_end_matches(".meta"));
                if data_path.exists() {
                    match std::fs::read(&p) {
                        Ok(bytes) => {
                            if let Ok(meta) = serde_json::from_slice::<Meta>(&bytes) {
                                metas.insert(meta.path.clone(), (meta, data_path));
                            } else {
                                // QUARANTINE, never delete: an unparsable sidecar
                                // next to a data file is far more likely a torn
                                // write than garbage worth destroying — deleting
                                // it (and then the "orphaned" data file) would
                                // silently erase a fully-acked stream. Park the
                                // sidecar, keep the data file untouched, and skip
                                // the stream loudly so an operator can repair.
                                eprintln!(
                                    "WARN: quarantining unparsable stream sidecar {} \
                                     (stream skipped this boot; data file kept)",
                                    p.display()
                                );
                                let _ = std::fs::rename(&p, p.with_extension("meta.corrupt"));
                                if let Some(id) = self.record_quarantined_stream(&data_path) {
                                    max_id = max_id.max(id);
                                }
                                quarantined.push(data_path);
                            }
                        }
                        Err(e) => {
                            // A transient READ error (EIO/EACCES) is not
                            // corruption: fail the boot rather than misclassify
                            // and destroy data.
                            return Err(std::io::Error::new(
                                e.kind(),
                                format!("failed to read stream sidecar {}: {e}", p.display()),
                            ));
                        }
                    }
                    continue;
                }
                // Sidecar with NO data file: stale leftover, safe to remove.
                let _ = std::fs::remove_file(&p);
            } else {
                data_files.push(p);
            }
        }
        // Drop orphan data files (no usable sidecar) — but NEVER a data file
        // whose sidecar was quarantined above.
        for p in data_files {
            if !metas.values().any(|(_, dp)| *dp == p) && !quarantined.contains(&p) {
                let _ = std::fs::remove_file(&p);
            }
        }
        let paths: Vec<String> = metas.keys().cloned().collect();
        // `visiting` tracks the active recursion stack to break cyclic
        // forked_from chains in corrupt sidecars (would otherwise overflow the
        // stack on boot). It self-empties between top-level calls.
        let mut visiting = HashSet::new();
        for path in paths {
            self.recover_one(&path, &metas, &mut visiting);
        }
        // Refcounts are denormalized lifecycle metadata. A crash can durably
        // remove the last child before persisting its parent's decrement, so
        // the recovered child->parent graph is authoritative when it is
        // complete. Persist reconciliation before seeding cleanup: another
        // crash must not restore a phantom reference and lose the tombstone
        // from the bounded recovery index again.
        self.reconcile_recovered_ref_counts(&metas, !quarantined.is_empty())?;
        // Recovered tombstones remain fenced. Zero-reference tombstones are
        // seeded into a bounded index for the runtime coordinator; recovery
        // never performs an unbounded synchronous unlink walk.
        for entry in self.streams.iter() {
            let st = entry.value();
            let shared = st.shared.read().unwrap();
            if shared.soft_deleted {
                st.fenced.store(true, Ordering::Release);
                st.deleted_tx.send_replace(true);
                if shared.ref_count == 0 {
                    self.recovered_retirements
                        .lock()
                        .unwrap()
                        .by_id
                        .insert(st.id, Arc::downgrade(st));
                }
            }
        }
        for (m, _) in metas.values() {
            max_id = max_id.max(m.id);
        }
        // Keep ids unique across restarts (they feed ETags).
        let cur = self.next_id.load(Ordering::Relaxed);
        self.next_id.store(cur.max(max_id + 1), Ordering::Relaxed);
        Ok(())
    }

    fn reconcile_recovered_ref_counts(
        &self,
        metas: &HashMap<String, (Meta, PathBuf)>,
        has_quarantined_streams: bool,
    ) -> std::io::Result<()> {
        let mut actual = HashMap::<String, u32>::new();
        let mut ambiguous = HashMap::<String, u32>::new();

        for (child_path, (meta, _)) in metas {
            let Some(parent_path) = meta.forked_from.as_ref() else {
                continue;
            };
            let Some(parent) = self.streams.get(parent_path).map(|entry| entry.clone()) else {
                continue;
            };
            let resolved = self
                .streams
                .get(child_path)
                .and_then(|child| child.parent.clone())
                .is_some_and(|source| Arc::ptr_eq(&source, &parent));
            if !resolved {
                // A parseable but corrupt/missing graph edge may still depend
                // on this parent. Never lower its persisted count from
                // incomplete evidence; raising to cover known edges is safe.
                let count = ambiguous.entry(parent_path.clone()).or_default();
                *count = count.checked_add(1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("recovery: too many ambiguous fork references to {parent_path}"),
                    )
                })?;
                continue;
            }
            let count = actual.entry(parent_path.clone()).or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("recovery: too many fork references to {parent_path}"),
                )
            })?;
        }

        for entry in self.streams.iter() {
            let st = entry.value().clone();
            let recovered = actual.get(&st.path).copied().unwrap_or(0);
            let ambiguous = ambiguous.get(&st.path).copied().unwrap_or(0);
            let conservatively_recovered = recovered.checked_add(ambiguous).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("recovery: too many total fork references to {}", st.path),
                )
            })?;
            let mut shared = st.shared.write().unwrap();
            let reconciled = if has_quarantined_streams || ambiguous != 0 {
                // An unreadable sidecar could hide an edge to any parent. This
                // may retain storage until operator repair, but cannot free
                // bytes still needed by a skipped child.
                shared.ref_count.max(conservatively_recovered)
            } else {
                recovered
            };
            if shared.ref_count == reconciled {
                continue;
            }
            shared.ref_count = reconciled;
            drop(shared);
            write_meta_sync_allow_fenced(&st, true).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "recovery: cannot durably reconcile fork references for {}: {error}",
                        st.path
                    ),
                )
            })?;
        }
        Ok(())
    }

    fn recover_one(
        &self,
        path: &str,
        metas: &HashMap<String, (Meta, PathBuf)>,
        visiting: &mut HashSet<String>,
    ) -> Option<Arc<StreamState>> {
        if let Some(existing) = self.streams.get(path) {
            return Some(existing.clone());
        }
        // Break a cyclic forked_from chain (corrupt sidecar) instead of recursing
        // forever. Removed on the way out so shared parents still resolve above.
        if !visiting.insert(path.to_string()) {
            return None;
        }
        let result = self.recover_one_inner(path, metas, visiting);
        visiting.remove(path);
        result
    }

    fn recover_one_inner(
        &self,
        path: &str,
        metas: &HashMap<String, (Meta, PathBuf)>,
        visiting: &mut HashSet<String>,
    ) -> Option<Arc<StreamState>> {
        let (meta, data_path) = metas.get(path)?;
        // Fork parents must be linked first (chains are acyclic; a parent always
        // outlives its forks, so a missing parent means corruption — skip).
        let parent = match &meta.forked_from {
            Some(src) => match self.recover_one(src, metas, visiting) {
                Some(p) => Some(p),
                // Nothing inherited → the fork stands alone; otherwise the
                // chain is broken (corruption) and the stream is skipped.
                None if meta.base_offset == 0 => None,
                None => return None,
            },
            None => None,
        };
        // A `pending_compaction` intent means a compaction crashed mid-flight. The
        // temp file (`compact.tmp`) holds the fsynced full residual `[cut, tail)`
        // (step 1's `sync_all` is NOT gated by fast), persisted durably BEFORE
        // the intent (`tier.rs`). So when the intent is durable, an intact temp is
        // the source of truth — finish the swap by promoting it. We must NOT trust
        // `p.tail - old_file_size` against the OLD live file: under `fast` the
        // old file's tail was never fsynced, so its on-disk size can be short,
        // which would both over-report `tail` AND skew `file_base` (C3).
        let tmp_path = data_path.with_extension("compact.tmp");
        if let Some(p) = &meta.pending_compaction {
            let want_residual = p.tail.checked_sub(p.new_file_base);
            let tmp_len = std::fs::metadata(&tmp_path).ok().map(|m| m.len());
            if let (Some(want), Some(have)) = (want_residual, tmp_len) {
                if have == want {
                    // Crash before the rename: promote the durable temp into place
                    // (idempotent — completes step 3). Now the live file IS the full
                    // residual regardless of the short un-synced old file.
                    let _ = std::fs::rename(&tmp_path, data_path);
                    let _ = fsync_parent_dir(data_path);
                }
                // else: a partial temp (intent not yet covering it) — fall through
                // and treat as post-rename (live file authoritative).
            }
        }
        // Remove any temp not promoted above (post-rename leftover, or a partial).
        let _ = std::fs::remove_file(&tmp_path);
        // A failed open/stat here is a RESOURCE error (EMFILE, EIO, perms) on a
        // data file whose sidecar just parsed — silently skipping the stream
        // (the old `.ok()?`) meant its WAL records were skipped at replay and
        // then destroyed by reset_after_recovery: acked-data loss with no log
        // line. Boot must fail loudly instead; the operator fixes the resource
        // limit and the data is still intact.
        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .append(true)
                .open(data_path)
                .unwrap_or_else(|e| {
                    panic!(
                        "recovery: cannot open stream data file {} ({e}); refusing \
                         to boot without it — skipping would let WAL reset destroy \
                         its acked records",
                        data_path.display()
                    )
                }),
        );
        let written = file
            .metadata()
            .unwrap_or_else(|e| {
                panic!(
                    "recovery: cannot stat stream data file {} ({e})",
                    data_path.display()
                )
            })
            .len();
        // `file_base` is the live file's logical start. With a `pending_compaction`
        // intent and the durable temp promoted above, the live file IS the full
        // residual `[new_file_base, tail)` — so `file_base = new_file_base`, derived
        // from the durable cut and NOT from `tail - file_size` (a short un-synced
        // file can't skew the mapping). If the temp was already gone (post-rename)
        // the live file is likewise the residual, detected by its size matching
        // `tail - new_file_base`. Only if neither holds (a full pre-rename old file
        // with no recoverable temp — not reachable once the intent is durable,
        // since the temp is fsynced first) do we fall back to the old
        // `tail - file_size` mapping. Without an intent, trust the persisted
        // `file_base` (defaulting to `base_offset` for pre-compaction sidecars).
        let (file_base, tail) = match meta.pending_compaction {
            Some(p) if written == p.tail.saturating_sub(p.new_file_base) => {
                // Live file is the residual (temp promoted, or crash after rename).
                (p.new_file_base, p.tail)
            }
            Some(p) if p.tail >= written => {
                // Fallback: a full old file still in place with no durable temp.
                (p.tail - written, p.tail)
            }
            Some(p) => (p.new_file_base, p.new_file_base + written),
            _ => {
                let fb = meta.file_base.unwrap_or(meta.base_offset);
                (fb, fb + written)
            }
        };
        let (tail_tx, _) = watch::channel(Tail {
            bytes: tail,
            closed: meta.closed,
        });
        let (deleted_tx, _) = watch::channel(meta.soft_deleted);
        let state = Arc::new(StreamState {
            id: meta.id,
            path: path.to_string(),
            is_json: is_json_content_type(&meta.content_type),
            file_path: data_path.clone(),
            base_offset: meta.base_offset,
            parent,
            boot_meta_durable_tail: meta.durable_tail,
            appender: AsyncMutex::new(Appender {
                file: file.clone(),
                written,
            }),
            shared: RwLock::new(Shared {
                tail,
                // Recovered/opened tail is durable by definition.
                durable_tail: tail,
                file_base,
                file,
                closed: meta.closed,
                closed_durable: meta.closed,
                closed_by: meta.closed_by.clone(),
                producers: meta.producers.clone(),
                last_seq_header: meta.last_seq_header.clone(),
                last_access: UNIX_EPOCH + Duration::from_secs(meta.last_access_unix),
                ref_count: meta.ref_count,
                soft_deleted: meta.soft_deleted,
            }),
            tail_tx,
            fenced: AtomicBool::new(meta.soft_deleted),
            inflight_appends: AtomicUsize::new(0),
            inflight_appends_zero: Notify::new(),
            retirement_queued: AtomicBool::new(false),
            wal_forgotten: AtomicBool::new(false),
            parent_released: AtomicBool::new(false),
            deleted_tx,
            meta_dirty: AtomicBool::new(false),
            // Epoch 0 < the shard's initial epoch (1), so the first append
            // registers this stream into the dirty set.
            dirty_epoch: AtomicU64::new(0),
            meta_lock: StdMutex::new(()),
            last_chunk: RwLock::new(None),
            tier: crate::tier::TierState::from_meta(
                &meta.segments,
                meta.sealed_offset,
                &self.segments_dir(),
            ),
            blobstore: self.blobstore.clone(),
            // A `pending_compaction` intent is re-derived deterministically from
            // the file size each boot (see `file_base` above), so the in-memory
            // cell starts clear; the next meta write persists the cleared marker.
            compaction: StdMutex::new(None),
            #[cfg(target_os = "linux")]
            sse_subs: StdMutex::new(None),
            config: StreamConfig {
                content_type: meta.content_type.clone(),
                ttl_seconds: meta.ttl_seconds,
                expires_at: meta
                    .expires_at_unix
                    .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
                expires_at_raw: meta.expires_at_raw.clone(),
                create_closed: meta.create_closed,
                forked_from: meta.forked_from.clone(),
                fork_offset_raw: meta.fork_offset_raw.clone(),
                fork_sub_offset: meta.fork_sub_offset,
            },
        });
        // Re-enqueue any sealed-but-not-yet-offloaded segments left by a crash
        // mid-offload (placement still Local while a remote tier is configured).
        self.reconcile_manifest_on_boot(&state);
        // A recovered `pending_compaction` intent must be durably CLEARED (with
        // the derived `file_base`) before this stream can accept appends: the
        // derivation branches assume the file length still matches the crash
        // moment, so "appends after boot + a second crash before any sidecar
        // write" would re-enter them with a grown file and mis-derive
        // `file_base` — shifting every subsequent live read AND replay write by
        // the appended delta (silent corruption). Persisting now closes that
        // double-crash window; a persist failure fails the boot loudly.
        if meta.pending_compaction.is_some() {
            write_meta_sync_inner(&state, true, meta.soft_deleted).unwrap_or_else(|e| {
                panic!(
                    "recovery: cannot durably clear the compaction intent for {} ({e}); \
                     booting without it risks a mis-derived file_base after another crash",
                    state.file_path.display()
                )
            });
        }
        self.streams.insert(path.to_string(), state.clone());
        if !meta.soft_deleted && state.has_expiration_policy() {
            self.register_expiring(&state);
        }
        Some(state)
    }

    fn register_expiring(&self, st: &Arc<StreamState>) {
        if !st.has_expiration_policy() {
            return;
        }
        self.expiring
            .lock()
            .unwrap()
            .by_id
            .insert(st.id, Arc::downgrade(st));
    }

    fn unregister_expiring(&self, stream_id: u64) {
        self.expiring.lock().unwrap().by_id.remove(&stream_id);
    }

    pub fn expiring_stream_count(&self) -> usize {
        self.expiring.lock().unwrap().by_id.len()
    }

    pub fn recovered_retirement_count(&self) -> usize {
        self.recovered_retirements.lock().unwrap().by_id.len()
    }

    fn select_index_page(
        index: &StdMutex<ExpiringStreams>,
        cursor: &mut ExpiryScanCursor,
        limit: usize,
    ) -> (Vec<(u64, Weak<StreamState>)>, bool) {
        if limit == 0 {
            return (Vec::new(), false);
        }
        let index = index.lock().unwrap();
        let total = index.by_id.len();
        if total == 0 {
            cursor.after = None;
            return (Vec::new(), true);
        }
        let want = limit.min(total);
        let mut selected = Vec::with_capacity(want);
        match cursor.after {
            None => selected.extend(
                index
                    .by_id
                    .iter()
                    .take(want)
                    .map(|(&id, weak)| (id, weak.clone())),
            ),
            Some(after) => {
                selected.extend(
                    index
                        .by_id
                        .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                        .take(want)
                        .map(|(&id, weak)| (id, weak.clone())),
                );
                if selected.len() < want {
                    selected.extend(
                        index
                            .by_id
                            .range((std::ops::Bound::Unbounded, std::ops::Bound::Included(after)))
                            .take(want - selected.len())
                            .map(|(&id, weak)| (id, weak.clone())),
                    );
                }
            }
        }
        let completed = selected.len() == total
            || cursor
                .after
                .is_some_and(|after| selected.iter().any(|(id, _)| *id <= after));
        cursor.after = selected.last().map(|(id, _)| *id);
        (selected, completed)
    }

    /// Inspect at most `limit` indexed streams, starting after the cursor and
    /// wrapping once. Weak references are cloned under the index lock; deadline
    /// evaluation and registry validation happen after it is released.
    pub fn scan_expiring(
        &self,
        cursor: &mut ExpiryScanCursor,
        limit: usize,
        now: SystemTime,
    ) -> ExpiryScanPage {
        let (selected, completed_pass) = Self::select_index_page(&self.expiring, cursor, limit);
        let checked = selected.len();
        let mut due = Vec::new();
        let mut oldest_due_deadline: Option<SystemTime> = None;
        for (stream_id, weak) in selected {
            let Some(stream) = weak.upgrade() else {
                self.unregister_expiring(stream_id);
                continue;
            };
            let deadline = {
                let shared = stream.shared.read().unwrap();
                stream.expiry_deadline_for(shared.last_access)
            };
            if deadline.is_some_and(|deadline| now > deadline) {
                oldest_due_deadline = match (oldest_due_deadline, deadline) {
                    (Some(oldest), Some(deadline)) => Some(oldest.min(deadline)),
                    (None, deadline) => deadline,
                    (oldest, None) => oldest,
                };
                due.push(ExpiryCandidate { stream_id, stream });
            }
        }
        ExpiryScanPage {
            checked,
            due,
            completed_pass,
            oldest_due_deadline,
        }
    }

    /// Page recovered zero-reference tombstones into the same bounded runtime
    /// coordinator used for live expiry. Candidates stay indexed until their
    /// exact hard-retirement step finalizes.
    pub fn scan_recovered_retirements(
        &self,
        cursor: &mut ExpiryScanCursor,
        limit: usize,
    ) -> ExpiryScanPage {
        let (selected, completed_pass) =
            Self::select_index_page(&self.recovered_retirements, cursor, limit);
        let checked = selected.len();
        let mut due = Vec::with_capacity(checked);
        for (stream_id, weak) in selected {
            let Some(stream) = weak.upgrade() else {
                self.recovered_retirements
                    .lock()
                    .unwrap()
                    .by_id
                    .remove(&stream_id);
                continue;
            };
            due.push(ExpiryCandidate { stream_id, stream });
        }
        ExpiryScanPage {
            checked,
            due,
            completed_pass,
            oldest_due_deadline: None,
        }
    }

    pub fn candidate_for(&self, st: &Arc<StreamState>) -> ExpiryCandidate {
        ExpiryCandidate {
            stream_id: st.id,
            stream: Arc::clone(st),
        }
    }

    pub(crate) fn is_current(&self, candidate: &ExpiryCandidate) -> bool {
        self.streams
            .get(&candidate.stream.path)
            .is_some_and(|current| {
                current.id == candidate.stream_id && Arc::ptr_eq(current.value(), &candidate.stream)
            })
    }

    /// Retain the exact registry owner's queue marker when a completed soft
    /// delete concurrently became a durable zero-reference tombstone. The
    /// registry mutex serializes this with joins and cascade ownership; the
    /// shared lock makes the soft-delete/refcount observation one snapshot.
    pub(crate) fn retain_zero_ref_soft_retirement(&self, candidate: &ExpiryCandidate) -> bool {
        let Some(current) = self.streams.get(&candidate.stream.path) else {
            return false;
        };
        if current.id != candidate.stream_id || !Arc::ptr_eq(current.value(), &candidate.stream) {
            return false;
        }
        let shared = candidate.stream.shared.read().unwrap();
        if !candidate.stream.fenced.load(Ordering::Acquire)
            || !shared.soft_deleted
            || shared.ref_count != 0
        {
            return false;
        }
        candidate
            .stream
            .retirement_queued
            .store(true, Ordering::Release);
        true
    }

    /// Atomic request lookup. `touch_ttl` is true for successful GET and
    /// compatible PUT, false for HEAD and control-path validation.
    pub fn lookup_at(&self, path: &str, now: SystemTime, touch_ttl: bool) -> StreamLookup {
        let Some(st) = self.streams.get(path).map(|entry| entry.clone()) else {
            return StreamLookup::Missing;
        };
        if touch_ttl && st.config.ttl_seconds.is_some() {
            // TTL renewal and retirement's final deadline/fence decision must
            // use the same exclusive guard.
            let mut shared = st.shared.write().unwrap();
            if shared.soft_deleted {
                drop(shared);
                return StreamLookup::Gone(st);
            }
            if st.fenced.load(Ordering::Acquire) || st.is_expired_with(&shared, now) {
                let _ =
                    st.fenced
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
                st.meta_dirty.store(false, Ordering::Release);
                drop(shared);
                st.publish_retirement_fence_wake();
                return StreamLookup::Expired(self.candidate_for(&st));
            }
            shared.last_access = now;
            drop(shared);
            return StreamLookup::Live(st);
        }

        // HEAD/control paths and streams without a sliding TTL stay on the
        // shared read lock in the overwhelmingly common live case.
        let shared = st.shared.read().unwrap();
        if shared.soft_deleted {
            drop(shared);
            return StreamLookup::Gone(st);
        }
        if st.fenced.load(Ordering::Acquire) {
            drop(shared);
            st.publish_retirement_fence_wake();
            return StreamLookup::Expired(self.candidate_for(&st));
        }
        if !st.is_expired_with(&shared, now) {
            drop(shared);
            return StreamLookup::Live(st);
        }
        drop(shared);

        // Upgrade only for the due case, then recheck. A racing TTL touch may
        // have renewed between locks; fencing under this write guard preserves
        // the touch-vs-retirement linearization.
        let shared = st.shared.write().unwrap();
        if shared.soft_deleted {
            drop(shared);
            return StreamLookup::Gone(st);
        }
        if !st.fenced.load(Ordering::Acquire) && !st.is_expired_with(&shared, now) {
            drop(shared);
            return StreamLookup::Live(st);
        }
        let _ = st
            .fenced
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
        st.meta_dirty.store(false, Ordering::Release);
        drop(shared);
        st.publish_retirement_fence_wake();
        StreamLookup::Expired(self.candidate_for(&st))
    }

    #[allow(dead_code)]
    pub fn get_at(&self, path: &str, now: SystemTime) -> Option<Arc<StreamState>> {
        match self.lookup_at(path, now, false) {
            StreamLookup::Missing => None,
            StreamLookup::Gone(st) | StreamLookup::Live(st) => Some(st),
            StreamLookup::Expired(candidate) => {
                // Compatibility path for synchronous internal callers. New HTTP
                // paths use lookup_at + prepare/transition/finish so a path is not
                // reused before subscription deletion persists.
                if candidate.stream.inflight_appends.load(Ordering::Acquire) == 0 {
                    candidate.stream.publish_retirement_fence_wake();
                    let _ =
                        self.finish_retirement_blocking(&candidate, RetirementDurability::Expiry);
                }
                None
            }
        }
    }

    pub async fn prepare_expiry_retirement(
        &self,
        candidate: &ExpiryCandidate,
        now: SystemTime,
    ) -> PrepareRetirement {
        if !self.is_current(candidate) {
            candidate.clear_queued();
            return PrepareRetirement::Stale;
        }
        {
            let shared = candidate.stream.shared.read().unwrap();
            if shared.soft_deleted
                && !(shared.ref_count == 0 && candidate.stream.fenced.load(Ordering::Acquire))
            {
                candidate.clear_queued();
                return PrepareRetirement::Gone;
            }
            if !candidate.stream.fenced.load(Ordering::Acquire)
                && !candidate.stream.is_expired_with(&shared, now)
            {
                candidate.clear_queued();
                return PrepareRetirement::Renewed;
            }
        }

        let appender = candidate.stream.appender.lock().await;
        if !self.is_current(candidate) {
            candidate.clear_queued();
            return PrepareRetirement::Stale;
        }
        {
            let shared = candidate.stream.shared.read().unwrap();
            if shared.soft_deleted
                && !(shared.ref_count == 0 && candidate.stream.fenced.load(Ordering::Acquire))
            {
                candidate.clear_queued();
                return PrepareRetirement::Gone;
            }
            if !candidate.stream.fenced.load(Ordering::Acquire) {
                if !candidate.stream.is_expired_with(&shared, now) {
                    candidate.clear_queued();
                    return PrepareRetirement::Renewed;
                }
                // Hold shared through the final check and the fence store so a
                // request-time TTL touch cannot interleave between them.
                candidate.stream.fenced.store(true, Ordering::Release);
            }
        }
        candidate.stream.meta_dirty.store(false, Ordering::Release);
        drop(appender);
        candidate.stream.publish_retirement_fence_wake();
        candidate.stream.wait_for_inflight_appends().await;
        PrepareRetirement::Ready
    }

    pub async fn prepare_delete(&self, st: &Arc<StreamState>) -> PrepareRetirement {
        let candidate = self.candidate_for(st);
        if !self.is_current(&candidate) {
            return PrepareRetirement::Stale;
        }
        let appender = st.appender.lock().await;
        if !self.is_current(&candidate) {
            return PrepareRetirement::Stale;
        }
        {
            let shared = st.shared.read().unwrap();
            if shared.soft_deleted {
                return PrepareRetirement::Gone;
            }
            st.fenced.store(true, Ordering::Release);
        }
        st.meta_dirty.store(false, Ordering::Release);
        drop(appender);
        st.publish_retirement_fence_wake();
        st.wait_for_inflight_appends().await;
        PrepareRetirement::Ready
    }

    /// Complete retirement after the caller has persisted the path-scoped
    /// subscription transition. Physical work is isolated on the blocking pool;
    /// WAL bookkeeping is forgotten only for a hard retirement.
    pub async fn finish_retirement(
        self: &Arc<Self>,
        candidate: &ExpiryCandidate,
        durability: RetirementDurability,
    ) -> std::io::Result<RetirementStep> {
        let store = Arc::clone(self);
        let work = candidate.clone();
        let physical = tokio::task::spawn_blocking(move || {
            store.finish_retirement_blocking_once(&work, durability)
        })
        .await
        .map_err(|error| std::io::Error::other(format!("retirement worker failed: {error}")))??;

        if physical.outcome == RetirementOutcome::Reaped {
            // The data and sidecar must be gone before WAL tail proof is
            // forgotten. Until both succeed, keep the exact fenced entry mapped
            // and queued so retry is identity-safe and idempotent.
            if let Some(wal) = self.wal.get() {
                wal.forget_stream(&candidate.stream).await?;
            }
            self.finalize_hard_retirement(candidate);
        }
        Ok(RetirementStep {
            outcome: physical.outcome,
            cascade: physical.cascade,
            reclaimed_local_bytes: physical.reclaimed_local_bytes,
        })
    }

    /// Look up a stream. Expired streams are removed (or soft-deleted when forks
    /// still reference them). Soft-deleted entries ARE returned — callers decide
    /// between 410 (direct ops) and 409 (PUT re-create / fork source).
    #[allow(dead_code)]
    pub fn get(&self, path: &str) -> Option<Arc<StreamState>> {
        self.get_at(path, SystemTime::now())
    }

    /// Hard-delete when nothing references the stream; soft-delete otherwise.
    ///
    /// NON-durable, detached variant for the expiry sweep on the read path: the
    /// on-disk removals / soft-meta write run on a fire-and-forget blocking
    /// task, so a crash can undo them (an expired stream re-expires on the next
    /// access — harmless). The DELETE handler must NOT use this: an acked
    /// DELETE undone by a crash resurrects the stream with all its data — use
    /// [`Store::delete_or_soft_delete_durable`] there.
    #[allow(dead_code)]
    pub fn delete_or_soft_delete(&self, st: &Arc<StreamState>) {
        let _ = self.delete_impl(st, false);
    }

    /// [`Store::delete_or_soft_delete`] with the DELETE-ack durability contract:
    /// the file + sidecar unlinks (and their parent-directory entry) — or the
    /// soft-delete meta flag — are durable on disk before this returns, so a
    /// post-ack crash can never resurrect the stream. Synchronous file I/O +
    /// fsync: call from a blocking context.
    #[allow(dead_code)]
    pub fn delete_or_soft_delete_durable(&self, st: &Arc<StreamState>) -> std::io::Result<()> {
        self.delete_impl(st, true)
    }

    fn delete_impl(&self, st: &Arc<StreamState>, durable: bool) -> std::io::Result<()> {
        {
            let shared = st.shared.read().unwrap();
            st.fenced.store(true, Ordering::Release);
            drop(shared);
        }
        st.meta_dirty.store(false, Ordering::Release);
        st.publish_retirement_fence_wake();
        if st.inflight_appends.load(Ordering::Acquire) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "stream retirement is waiting for in-flight appends",
            ));
        }
        let candidate = self.candidate_for(st);
        self.finish_retirement_blocking(
            &candidate,
            if durable {
                RetirementDurability::Explicit
            } else {
                RetirementDurability::Expiry
            },
        )?;
        Ok(())
    }

    pub fn finish_retirement_blocking(
        &self,
        candidate: &ExpiryCandidate,
        durability: RetirementDurability,
    ) -> std::io::Result<RetirementOutcome> {
        let mut current = candidate.clone();
        let mut hard = Vec::new();
        loop {
            let step = self.finish_retirement_blocking_once(&current, durability)?;
            match step.outcome {
                RetirementOutcome::SoftDeleted => return Ok(step.outcome),
                RetirementOutcome::Reaped => hard.push(current),
            }
            match step.cascade {
                Some(parent) => current = parent,
                None => break,
            }
        }
        for retired in hard {
            self.finalize_hard_retirement(&retired);
        }
        Ok(RetirementOutcome::Reaped)
    }

    fn finish_retirement_blocking_once(
        &self,
        candidate: &ExpiryCandidate,
        durability: RetirementDurability,
    ) -> std::io::Result<PhysicalRetirementStep> {
        let st = &candidate.stream;
        if !st.fenced.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "retirement completion requires a fenced stream",
            ));
        }
        if st.inflight_appends.load(Ordering::Acquire) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "stream retirement is waiting for in-flight appends",
            ));
        }

        // Serialize the refcount decision with fork source reservation and all
        // sidecar writers. A reservation that won before the fence completes
        // (or rolls back) before this decision; ordinary appender activity is
        // deliberately unrelated.
        let _meta = st.meta_lock.lock().unwrap_or_else(|e| e.into_inner());
        let soft = {
            let mut s = st.shared.write().unwrap();
            if s.ref_count > 0 {
                s.soft_deleted = true;
                true
            } else {
                false
            }
        };
        if soft {
            #[cfg(test)]
            if DELETE_FAULT.load(Ordering::Relaxed) == 1 {
                st.shared.write().unwrap().soft_deleted = false;
                return Err(std::io::Error::other(
                    "injected soft-delete metadata failure",
                ));
            }
            if let Err(error) =
                write_meta_sync_locked(st, durability == RetirementDurability::Explicit, true)
            {
                st.shared.write().unwrap().soft_deleted = false;
                return Err(error);
            }
            self.publish_inventory(st);
            self.unregister_expiring(candidate.stream_id);
            candidate.clear_queued();
            Ok(PhysicalRetirementStep {
                outcome: RetirementOutcome::SoftDeleted,
                cascade: None,
                reclaimed_local_bytes: 0,
            })
        } else {
            let fp = st.file_path.clone();
            let reclaimed_local_bytes = {
                // The metadata barrier acquired above stays held through unlink
                // so no deferred writer can recreate the sidecar afterwards.
                #[cfg(test)]
                if DELETE_FAULT.load(Ordering::Relaxed) == 2 {
                    return Err(std::io::Error::other(
                        "injected hard-delete durability failure",
                    ));
                }
                let mut reclaimed = remove_file_if_present_measured(&meta_path(&fp))?;
                reclaimed = reclaimed.saturating_add(remove_file_if_present_measured(&fp)?);
                if durability == RetirementDurability::Explicit {
                    fsync_parent_dir(&fp)?;
                }
                reclaimed
            };
            // Safe only after a true hard delete with no remaining fork refs.
            self.gc_remote_segments(st);
            let cascade = self.release_parent_once(st, durability)?;
            Ok(PhysicalRetirementStep {
                outcome: RetirementOutcome::Reaped,
                cascade,
                reclaimed_local_bytes,
            })
        }
    }

    fn finalize_hard_retirement(&self, candidate: &ExpiryCandidate) {
        let st = &candidate.stream;
        self.streams
            .remove_if(&st.path, |_, current| Arc::ptr_eq(current, st));
        self.remove_inventory(&st.path, candidate.stream_id);
        self.unregister_expiring(candidate.stream_id);
        self.recovered_retirements
            .lock()
            .unwrap()
            .by_id
            .remove(&candidate.stream_id);
        candidate.clear_queued();
    }

    /// Decrement one parent's fork refcount. A zero-reference soft parent is
    /// returned as the next exact candidate; the bounded coordinator performs
    /// its WAL and physical cleanup before any path in the chain is reusable.
    fn release_parent_once(
        &self,
        st: &Arc<StreamState>,
        durability: RetirementDurability,
    ) -> std::io::Result<Option<ExpiryCandidate>> {
        let Some(parent) = st.parent.clone() else {
            return Ok(None);
        };
        if st
            .parent_released
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            let shared = parent.shared.read().unwrap();
            return Ok(
                (shared.soft_deleted && shared.ref_count == 0).then(|| self.candidate_for(&parent))
            );
        }
        // Child retirement already holds the child's metadata barrier. Taking
        // the parent's barrier here is the established leaf-to-root lifecycle
        // order; fork creation can take source then child only while that child
        // is still unpublished, so no live operation can acquire the reverse
        // pair. Besides serializing retirement and fork reservations, this lets
        // us merge only the authoritative refcount into the durable sidecar:
        // a live parent append may have speculative close/dedupe/TTL fields in
        // `Shared` while it is still waiting for WAL durability.
        let _parent_meta = parent
            .meta_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let gone = {
            let mut shared = parent.shared.write().unwrap();
            shared.ref_count = shared.ref_count.saturating_sub(1);
            shared.soft_deleted && shared.ref_count == 0
        };
        if gone {
            let was_meta_dirty = parent.meta_dirty.swap(false, Ordering::AcqRel);
            // Expiry normally permits an unlink to be undone by a crash. The
            // zero-ref parent transition is different: once persisted, recovery
            // may collect the parent. Make the child's prior unlink durable
            // first (important when stream lanes put child and parent in
            // different directories), so recovery can never observe a live
            // child beside a durably zero-reference parent.
            if durability == RetirementDurability::Expiry {
                if let Err(error) = fsync_parent_dir(&st.file_path) {
                    parent.shared.write().unwrap().ref_count += 1;
                    parent.meta_dirty.store(was_meta_dirty, Ordering::Release);
                    st.parent_released.store(false, Ordering::Release);
                    return Err(error);
                }
            }
            // This is the authoritative transition that makes a recovered soft
            // tombstone independently collectible. Persist and directory-sync
            // it before handing the parent to a separately paced cascade step;
            // a crash in that gap must not restore a phantom reference.
            if let Err(error) = write_ref_count_meta_sync_locked(&parent, true) {
                parent.shared.write().unwrap().ref_count += 1;
                parent.meta_dirty.store(was_meta_dirty, Ordering::Release);
                st.parent_released.store(false, Ordering::Release);
                return Err(error);
            }
            return Ok(Some(self.candidate_for(&parent)));
        }
        // Persist only the decremented refcount. This also works for a retained
        // fenced parent because the narrow lifecycle merge intentionally does
        // not apply the ordinary full-snapshot fence check.
        if let Err(error) =
            write_ref_count_meta_sync_locked(&parent, durability == RetirementDurability::Explicit)
        {
            parent.shared.write().unwrap().ref_count += 1;
            st.parent_released.store(false, Ordering::Release);
            return Err(error);
        }
        Ok(None)
    }

    pub fn create(
        &self,
        path: &str,
        config: StreamConfig,
        parent: Option<Arc<StreamState>>,
        base_offset: u64,
    ) -> std::io::Result<CreateResult> {
        use dashmap::mapref::entry::Entry;
        // Published streams need no creation serialization.
        if let Some(existing) = self.streams.get(path).map(|entry| entry.clone()) {
            return Ok(self.evaluate_existing_create(existing, &config, SystemTime::now()));
        }

        // The path stripe, not the DashMap shard, serializes same-path PUTs.
        // Retain it through durable sidecar publication so no second creator
        // can observe the path as absent and start a competing transaction.
        let stripe = self.streams.hash_usize(&path) & (CREATE_PATH_LOCK_STRIPES - 1);
        let _creation = self.creation_stripes[stripe]
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        // Recheck after acquiring the stripe: a creator that won while this
        // thread was waiting has now durably published its state. A retiring
        // incarnation stays mapped and fenced until exact finalization, so this
        // check also prevents path reuse from racing physical retirement.
        if let Some(existing) = self.streams.get(path).map(|entry| entry.clone()) {
            return Ok(self.evaluate_existing_create(existing, &config, SystemTime::now()));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let fname = format!("{}~{}", encode_path(path), id);
        let file_path = lane_dir(&self.data_dir, lane_of(&fname)).join(fname);
        let file = Arc::new(
            OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(&file_path)?,
        );
        let is_json = is_json_content_type(&config.content_type);
        let closed = config.create_closed;
        let (tail_tx, _) = watch::channel(Tail {
            bytes: base_offset,
            closed,
        });
        let (deleted_tx, _) = watch::channel(false);
        let state = Arc::new(StreamState {
            id,
            path: path.to_string(),
            is_json,
            file_path,
            base_offset,
            parent: parent.clone(),
            // Live-created stream: the durable frontier IS the initial tail (the
            // create meta below persists it). Only consulted by boot recovery.
            boot_meta_durable_tail: Some(base_offset),
            appender: AsyncMutex::new(Appender {
                file: file.clone(),
                written: 0,
            }),
            shared: RwLock::new(Shared {
                tail: base_offset,
                durable_tail: base_offset,
                file_base: base_offset,
                file,
                closed,
                closed_durable: closed,
                closed_by: None,
                producers: HashMap::new(),
                last_seq_header: None,
                last_access: SystemTime::now(),
                ref_count: 0,
                soft_deleted: false,
            }),
            tail_tx,
            fenced: AtomicBool::new(false),
            inflight_appends: AtomicUsize::new(0),
            inflight_appends_zero: Notify::new(),
            retirement_queued: AtomicBool::new(false),
            wal_forgotten: AtomicBool::new(false),
            parent_released: AtomicBool::new(false),
            deleted_tx,
            meta_dirty: AtomicBool::new(false),
            // Epoch 0 < the shard's initial epoch (1), so the first append
            // registers this stream into the dirty set.
            dirty_epoch: AtomicU64::new(0),
            meta_lock: StdMutex::new(()),
            last_chunk: RwLock::new(None),
            tier: crate::tier::TierState::default(),
            blobstore: self.blobstore.clone(),
            compaction: StdMutex::new(None),
            #[cfg(target_os = "linux")]
            sse_subs: StdMutex::new(None),
            config,
        });
        // Serialize the source refcount sidecar transaction with physical
        // retirement, but never with ordinary appends. The shared write lock is
        // the fence/ref reservation linearization: if this increment wins,
        // retirement later observes the ref and soft-deletes; if the fence
        // wins, creation rejects the source.
        let _parent_meta = parent.as_ref().map(|parent| {
            parent
                .meta_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner())
        });
        if let Some(parent) = &parent {
            let mut shared = parent.shared.write().unwrap();
            let unavailable = parent.fenced.load(Ordering::Acquire)
                || shared.soft_deleted
                || parent.is_expired_with(&shared, SystemTime::now());
            if unavailable {
                drop(shared);
                let _ = std::fs::remove_file(&state.file_path);
                return Ok(CreateResult::SourceUnavailable);
            }
            shared.ref_count += 1;
            drop(shared);
        }
        #[cfg(test)]
        pause_create_before_meta_and_inject_failure(&state);
        // Persist only the source's refcount field from its existing durable
        // sidecar. An admitted append may already have mutated close/dedupe/TTL
        // fields in `Shared` while it waits for WAL durability; a full
        // Meta::capture here would make that unacknowledged snapshot durable as
        // a side effect of forking. The source metadata barrier still
        // serializes this narrow merge with retirement and every other sidecar
        // writer.
        //
        // The child remains unpublished until both writes are durable, so
        // rollback cannot erase an acknowledged child append. A reservation
        // that linearized just before a retirement fence is still authoritative:
        // the narrow writer deliberately does not reject a now-fenced source.
        let created = (|| -> std::io::Result<()> {
            if let Some(p) = &parent {
                if let Err(e) = write_ref_count_meta_sync_locked(p, true) {
                    let mut shared = p.shared.write().unwrap();
                    shared.ref_count = shared.ref_count.saturating_sub(1);
                    drop(shared);
                    let _ = write_ref_count_meta_sync_locked(p, true);
                    return Err(e);
                }
            }
            if let Err(e) = write_meta_sync(&state, true) {
                if let Some(p) = &parent {
                    let mut shared = p.shared.write().unwrap();
                    shared.ref_count = shared.ref_count.saturating_sub(1);
                    drop(shared);
                    let _ = write_ref_count_meta_sync_locked(p, true);
                }
                return Err(e);
            }
            Ok(())
        })();
        if let Err(e) = created {
            // The state was never published, so rollback only has unpublished
            // local artifacts to undo.
            let _ = std::fs::remove_file(&state.file_path);
            return Err(e);
        }

        // Make the short registry + projection publication atomic with respect
        // to physical retirement. Once the state enters `streams`, retirement
        // can discover and fence it, but cannot pass its metadata barrier until
        // inventory and expiration registration are both visible.
        let publication_meta = state
            .meta_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match self.streams.entry(path.to_string()) {
            Entry::Vacant(v) => {
                v.insert(state.clone());
            }
            Entry::Occupied(e) => {
                // All runtime creators take the same path stripe, so this is a
                // defensive no-replacement branch rather than an expected race.
                // Release the short DashMap guard before rolling back I/O.
                let existing = e.get().clone();
                drop(e);
                let mut first_error = None;
                if let Err(error) = remove_file_if_present_measured(&meta_path(&state.file_path)) {
                    first_error = Some(error);
                }
                if let Err(error) = remove_file_if_present_measured(&state.file_path) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                if let Err(error) = fsync_parent_dir(&state.file_path) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                if let Some(p) = &parent {
                    let previous_ref_count = {
                        let mut shared = p.shared.write().unwrap();
                        let previous = shared.ref_count;
                        shared.ref_count = shared.ref_count.saturating_sub(1);
                        previous
                    };
                    if let Err(error) = write_ref_count_meta_sync_locked(p, true) {
                        p.shared.write().unwrap().ref_count = previous_ref_count;
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
                if let Some(error) = first_error {
                    return Err(error);
                }
                return Ok(self.evaluate_existing_create(
                    existing,
                    &state.config,
                    SystemTime::now(),
                ));
            }
        }
        // Fork source reservation is fully durable, and physical retirement of
        // the now-visible child remains excluded by `publication_meta`. Release
        // source-before-child nesting before any test pause or projection work.
        drop(_parent_meta);
        #[cfg(test)]
        pause_create_after_insert(&state);
        self.publish_inventory(&state);
        self.register_expiring(&state);
        drop(publication_meta);
        Ok(CreateResult::Created(state))
    }
}

#[cfg(test)]
static DELETE_FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
struct CreateBeforeMetaHook {
    data_dir: PathBuf,
    path: String,
    claimed: AtomicBool,
    reached: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(test)]
static CREATE_BEFORE_META_HOOKS: StdMutex<Vec<Arc<CreateBeforeMetaHook>>> =
    StdMutex::new(Vec::new());

#[cfg(test)]
struct CreateBeforeMetaHookGuard {
    hook: Arc<CreateBeforeMetaHook>,
}

#[cfg(test)]
impl CreateBeforeMetaHookGuard {
    fn reached(&self) {
        self.hook.reached.wait();
    }

    fn release(&self) {
        self.hook.release.wait();
    }
}

#[cfg(test)]
impl Drop for CreateBeforeMetaHookGuard {
    fn drop(&mut self) {
        let mut installed = CREATE_BEFORE_META_HOOKS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        installed.retain(|hook| !Arc::ptr_eq(hook, &self.hook));
    }
}

#[cfg(test)]
fn install_create_before_meta_failure_hook(
    data_dir: &std::path::Path,
    path: &str,
) -> CreateBeforeMetaHookGuard {
    let hook = Arc::new(CreateBeforeMetaHook {
        data_dir: data_dir.to_path_buf(),
        path: path.to_owned(),
        claimed: AtomicBool::new(false),
        reached: std::sync::Barrier::new(2),
        release: std::sync::Barrier::new(2),
    });
    let mut installed = CREATE_BEFORE_META_HOOKS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(
        !installed.iter().any(|installed| {
            installed.data_dir == hook.data_dir && installed.path == hook.path
        }),
        "a create test hook is already installed for this store and path"
    );
    installed.push(Arc::clone(&hook));
    CreateBeforeMetaHookGuard { hook }
}

#[cfg(test)]
fn pause_create_before_meta_and_inject_failure(st: &StreamState) {
    let hook = CREATE_BEFORE_META_HOOKS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .find(|hook| {
            st.path == hook.path
                && st.file_path.starts_with(hook.data_dir.join("streams"))
                && hook
                    .claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
        })
        .cloned();
    if let Some(hook) = hook {
        let tmp = meta_path(&st.file_path).with_extension("meta.tmp");
        std::fs::create_dir(&tmp).expect("create hook injects a sidecar temp-path failure");
        hook.reached.wait();
        hook.release.wait();
    }
}

#[cfg(test)]
struct CreateAfterInsertHook {
    data_dir: PathBuf,
    path: String,
    claimed: AtomicBool,
    reached: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(test)]
static CREATE_AFTER_INSERT_HOOKS: StdMutex<Vec<Arc<CreateAfterInsertHook>>> =
    StdMutex::new(Vec::new());

#[cfg(test)]
struct CreateAfterInsertHookGuard {
    hook: Arc<CreateAfterInsertHook>,
}

#[cfg(test)]
impl CreateAfterInsertHookGuard {
    fn reached(&self) {
        self.hook.reached.wait();
    }

    fn release(&self) {
        self.hook.release.wait();
    }
}

#[cfg(test)]
impl Drop for CreateAfterInsertHookGuard {
    fn drop(&mut self) {
        let mut installed = CREATE_AFTER_INSERT_HOOKS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        installed.retain(|hook| !Arc::ptr_eq(hook, &self.hook));
    }
}

#[cfg(test)]
fn install_create_after_insert_hook(
    data_dir: &std::path::Path,
    path: &str,
) -> CreateAfterInsertHookGuard {
    let hook = Arc::new(CreateAfterInsertHook {
        data_dir: data_dir.to_path_buf(),
        path: path.to_owned(),
        claimed: AtomicBool::new(false),
        reached: std::sync::Barrier::new(2),
        release: std::sync::Barrier::new(2),
    });
    let mut installed = CREATE_AFTER_INSERT_HOOKS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(
        !installed.iter().any(|installed| {
            installed.data_dir == hook.data_dir && installed.path == hook.path
        }),
        "an after-insert hook is already installed for this store and path"
    );
    installed.push(Arc::clone(&hook));
    CreateAfterInsertHookGuard { hook }
}

#[cfg(test)]
fn pause_create_after_insert(st: &StreamState) {
    let hook = CREATE_AFTER_INSERT_HOOKS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .find(|hook| {
            st.path == hook.path
                && st.file_path.starts_with(hook.data_dir.join("streams"))
                && hook
                    .claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
        })
        .cloned();
    if let Some(hook) = hook {
        hook.reached.wait();
        hook.release.wait();
    }
}

fn config_matches_with_closed(
    existing: &StreamState,
    requested: &StreamConfig,
    closed_now: bool,
) -> bool {
    let ex = &existing.config;
    media_type(&ex.content_type) == media_type(&requested.content_type)
        && ex.ttl_seconds == requested.ttl_seconds
        && ex.expires_at_raw == requested.expires_at_raw
        && ex.forked_from == requested.forked_from
        && ex.fork_offset_raw == requested.fork_offset_raw
        && ex.fork_sub_offset.unwrap_or(0) == requested.fork_sub_offset.unwrap_or(0)
        // PUT without Stream-Closed against a closed stream is a conflict.
        && (requested.create_closed == closed_now)
}

pub fn media_type(ct: &str) -> String {
    ct.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

pub fn is_json_content_type(ct: &str) -> bool {
    media_type(ct) == "application/json"
}

fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('+');
        }
    }
    if out.len() > 120 {
        out.truncate(120);
    }
    out
}

/// A physical read: `len` bytes starting at `file_start` in `file`.
pub struct Segment {
    pub file: Arc<File>,
    pub file_start: u64,
    pub len: u64,
}

impl Segment {
    /// Exclusive end byte position in the file (`file_start + len`).
    pub fn file_end(&self) -> u64 {
        self.file_start + self.len
    }
}

/// Read all `segments` into one contiguous buffer. Returns empty bytes if any
/// positioned read fails (e.g. the file was removed mid-read). Shared by the
/// buffered read paths (SSE batches, small inline reads).
pub fn materialize_segments(segments: &[Segment]) -> bytes::Bytes {
    use bytes::BytesMut;
    use std::os::unix::fs::FileExt;
    let total: usize = segments.iter().map(|s| s.len as usize).sum();
    let mut buf = BytesMut::zeroed(total);
    let mut at = 0;
    for seg in segments {
        let n = seg.len as usize;
        if seg
            .file
            .read_exact_at(&mut buf[at..at + n], seg.file_start)
            .is_err()
        {
            return bytes::Bytes::new();
        }
        at += n;
    }
    buf.freeze()
}

// ---------------- hot/cold tiering: sealing, offload, resolution, GC ----------------

/// Build the configured remote blobstore, if any. Off → None. Local → a
/// filesystem-backed blobstore under `<data_dir>/cold` (or the configured dir).
/// S3 → the object_store adapter (feature `tier` only).
fn build_blobstore(
    cfg: &crate::tier::TierConfig,
    data_dir: &std::path::Path,
) -> std::io::Result<Option<crate::blobstore::SharedBlobStore>> {
    use crate::tier::TierKind;
    match cfg.kind {
        TierKind::Off => Ok(None),
        TierKind::Local => {
            let dir = cfg
                .local_dir
                .clone()
                .unwrap_or_else(|| data_dir.join("cold"));
            let bs = crate::blobstore::LocalFsBlobStore::new(dir)?;
            Ok(Some(Arc::new(bs)))
        }
        TierKind::S3 => {
            #[cfg(feature = "tier")]
            {
                let bs = crate::blobstore::S3BlobStore::new(cfg)?;
                Ok(Some(Arc::new(bs)))
            }
            #[cfg(not(feature = "tier"))]
            {
                let _ = cfg;
                Err(std::io::Error::other(
                    "--tier s3 requires building with `--features tier`",
                ))
            }
        }
    }
}

// The hot/cold tiering lifecycle (sealing, offload, GC, boot reconcile) and the
// placement-aware read resolver live in `tier.rs`. Re-export the read API here so
// callers keep a single `store::` facade for resolving a logical range.
pub use crate::tier::{into_local_segments, resolve_range, ResolvedSlice};

// ---------------- metadata persistence & recovery ----------------

/// On-disk metadata sidecar (`<data file>.meta`). Create/close/delete write it
/// synchronously with fsync; producer/access updates flush debounced without
/// fsync (documented guarantee: after a crash, producer dedup state may lag the
/// data file — producers should bump their epoch on restart, per PROTOCOL.md).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Meta {
    pub id: u64,
    pub path: String,
    pub content_type: String,
    pub ttl_seconds: Option<u64>,
    pub expires_at_unix: Option<u64>,
    pub expires_at_raw: Option<String>,
    pub create_closed: bool,
    pub forked_from: Option<String>,
    pub fork_offset_raw: Option<String>,
    pub fork_sub_offset: Option<u64>,
    pub base_offset: u64,
    pub closed: bool,
    pub closed_by: Option<(String, u64, u64)>,
    pub producers: HashMap<String, ProducerState>,
    pub last_seq_header: Option<String>,
    pub last_access_unix: u64,
    pub ref_count: u32,
    pub soft_deleted: bool,
    /// Hot/cold tiering manifest. Empty for streams that never sealed (the
    /// default). `#[serde(default)]` keeps sidecars written by the pre-tiering
    /// server fully forward/backward compatible.
    #[serde(default)]
    pub segments: Vec<MetaSegment>,
    #[serde(default)]
    pub sealed_offset: u64,
    /// Logical start of the live data file (compaction watermark). `None` in
    /// pre-compaction sidecars → recovery falls back to `base_offset`, so old
    /// sidecars stay fully compatible.
    #[serde(default)]
    pub file_base: Option<u64>,
    /// Set only while a compaction is mid-flight; drives crash recovery. Cleared
    /// once the rewrite + swap completes durably.
    #[serde(default)]
    pub pending_compaction: Option<PendingCompaction>,
    /// The stream's durable frontier (logical bytes) when this sidecar was
    /// written — WAL recovery's per-stream truncation proof for streams with NO
    /// retained WAL record and NO checkpoint `tails` entry (e.g. a stream
    /// created after the last checkpoint whose only in-flight append was torn
    /// by power loss). Only ever holds values that were durable at capture
    /// time; a lagging (lazily-flushed) value is safe because recovery takes
    /// the max of every proof. `None` in sidecars written by older servers →
    /// recovery falls back to trusting the file size (the pre-field behavior).
    #[serde(default)]
    pub durable_tail: Option<u64>,
}

/// Serialized form of a sealed-segment manifest entry.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MetaSegment {
    pub logical_start: u64,
    pub len: u64,
    /// When set, the segment is offloaded to the remote tier under this key.
    /// When None, it is still a local chunk file (path derived from the stream's
    /// data file + index, see segment_file_path).
    pub remote_key: Option<String>,
    /// File name of the local chunk file (relative to the segments dir) when not
    /// yet remote. None once offloaded.
    pub local_file: Option<String>,
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Meta {
    fn capture(st: &StreamState) -> Meta {
        let seg_snapshot: (Vec<MetaSegment>, u64) = {
            let m = st.tier.manifest.lock().unwrap();
            (
                m.segments
                    .iter()
                    .map(|seg| match &seg.placement {
                        crate::tier::Placement::Local(p) => MetaSegment {
                            logical_start: seg.logical_start,
                            len: seg.len,
                            remote_key: None,
                            local_file: p
                                .file_name()
                                .and_then(|n| n.to_str())
                                .map(|s| s.to_string()),
                        },
                        crate::tier::Placement::Remote(key) => MetaSegment {
                            logical_start: seg.logical_start,
                            len: seg.len,
                            remote_key: Some(key.clone()),
                            local_file: None,
                        },
                    })
                    .collect(),
                m.sealed_offset,
            )
        };
        let s = st.shared.read().unwrap();
        Meta {
            id: st.id,
            path: st.path.clone(),
            content_type: st.config.content_type.clone(),
            ttl_seconds: st.config.ttl_seconds,
            expires_at_unix: st.config.expires_at.map(unix_secs),
            expires_at_raw: st.config.expires_at_raw.clone(),
            create_closed: st.config.create_closed,
            forked_from: st.config.forked_from.clone(),
            fork_offset_raw: st.config.fork_offset_raw.clone(),
            fork_sub_offset: st.config.fork_sub_offset,
            base_offset: st.base_offset,
            closed: s.closed,
            closed_by: s.closed_by.clone(),
            producers: s.producers.clone(),
            last_seq_header: s.last_seq_header.clone(),
            last_access_unix: unix_secs(s.last_access),
            ref_count: s.ref_count,
            soft_deleted: s.soft_deleted,
            // segments + sealed_offset MUST come from ONE lock acquisition: a
            // seal pass interleaving between two separate acquisitions would
            // yield a capture whose sealed_offset covers a region absent from
            // `segments` — persisted, that is a permanent manifest hole below
            // the watermark (reads resolve nothing there; the sealer never
            // re-seals it).
            segments: seg_snapshot.0,
            sealed_offset: seg_snapshot.1,
            file_base: Some(s.file_base),
            pending_compaction: *st.compaction.lock().unwrap(),
            durable_tail: Some(s.durable_tail),
        }
    }
}

pub fn meta_path(file_path: &std::path::Path) -> PathBuf {
    let mut p = file_path.as_os_str().to_owned();
    p.push(".meta");
    PathBuf::from(p)
}

/// Write the metadata sidecar. `durable` forces an fsync (create/close/delete).
pub fn write_meta_sync(st: &StreamState, durable: bool) -> std::io::Result<()> {
    write_meta_sync_inner(st, durable, false)
}

fn write_meta_sync_allow_fenced(st: &StreamState, durable: bool) -> std::io::Result<()> {
    write_meta_sync_inner(st, durable, true)
}

fn write_meta_sync_inner(
    st: &StreamState,
    durable: bool,
    allow_fenced: bool,
) -> std::io::Result<()> {
    // Serialize per stream so concurrent writers don't race on the temp file or
    // reorder renames (a stale flush must not clobber a durable manifest flip).
    let _g = st.meta_lock.lock().unwrap_or_else(|e| e.into_inner());
    write_meta_sync_locked(st, durable, allow_fenced)
}

/// Write metadata while the caller holds `st.meta_lock`. This is used only for
/// a multi-sidecar lifecycle transaction (fork source reservation + child
/// create), where retirement must not persist an intermediate refcount.
fn write_meta_sync_locked(
    st: &StreamState,
    durable: bool,
    allow_fenced: bool,
) -> std::io::Result<()> {
    // This check must happen inside `meta_lock`: retirement holds the same lock
    // through unlink, closing check→unlink→rename sidecar resurrection races.
    if st.fenced.load(Ordering::Acquire) && !allow_fenced {
        return Ok(());
    }
    let meta = Meta::capture(st);
    write_meta_value_sync_locked(st, &meta, durable)
}

/// Merge the in-memory fork refcount into the last durable sidecar without
/// capturing any other live `Shared` fields. The caller holds `st.meta_lock`,
/// which makes the read/modify/rename atomic with respect to every full sidecar
/// writer and the retirement unlink decision.
fn write_ref_count_meta_sync_locked(st: &StreamState, durable: bool) -> std::io::Result<()> {
    let final_path = meta_path(&st.file_path);
    let bytes = std::fs::read(&final_path)?;
    let mut meta: Meta = serde_json::from_slice(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "cannot update fork refcount in {}: {error}",
                final_path.display()
            ),
        )
    })?;
    if meta.id != st.id || meta.path != st.path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "cannot update fork refcount in {}: sidecar identity does not match stream",
                final_path.display()
            ),
        ));
    }
    meta.ref_count = st.shared.read().unwrap().ref_count;
    write_meta_value_sync_locked(st, &meta, durable)
}

/// Serialize an already-selected metadata snapshot while the caller holds
/// `st.meta_lock`.
fn write_meta_value_sync_locked(
    st: &StreamState,
    meta: &Meta,
    durable: bool,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(meta).expect("meta serializes");
    let tmp = meta_path(&st.file_path).with_extension("meta.tmp");
    let final_path = meta_path(&st.file_path);
    {
        use std::io::Write;
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        // ALWAYS sync the tmp's data before the rename — even for the
        // "non-durable" lagging flushes. Renaming an unsynced tmp over the
        // previously-durable sidecar lets a power crash land the rename with
        // zero-length/garbage content (no ext4-style rename heuristic on all
        // filesystems), and boot treats an unparsable sidecar as corruption.
        // The `durable` flag now only gates the parent-dir fsync (rename
        // persistence), preserving the lagging-flush contract's cheapness.
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)?;
    // A rename is crash-durable only once the parent dir entry is fsynced.
    if durable {
        fsync_parent_dir(&final_path)?;
    }
    Ok(())
}

/// fsync the directory containing `path`, making a prior create/rename in that
/// directory crash-durable. A POSIX directory fd supports fsync; `sync_all`
/// issues it.
pub(crate) fn fsync_parent_dir(path: &std::path::Path) -> std::io::Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => File::open(dir)?.sync_all(),
        _ => Ok(()),
    }
}

fn remove_file_if_present_measured(path: &std::path::Path) -> std::io::Result<u64> {
    let bytes = match std::fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    match std::fs::remove_file(path) {
        Ok(()) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

impl Store {
    /// Queue a non-durable meta sidecar flush (producer/access updates) for the
    /// next periodic sweep (#4691). Replaces the per-stream 100 ms debounce
    /// timer, which cost a tokio timer task + `spawn_blocking` + full sidecar
    /// rewrite per stream per 100 ms — at high stream cardinality ~5x wal-mode
    /// CPU for the same load. The lag bound moves from the 100 ms debounce to
    /// the sweep cadence, exactly the trade wal mode made in #4675.
    ///
    /// The `meta_dirty` CAS dedupes: while a flush is pending the stream sits
    /// in `meta_sweep` at most once. The wal-mode append path never calls this
    /// — it stores `meta_dirty` directly and the shard checkpoint flushes the
    /// sidecar (see `handle_append_inner`); if that path already set the flag,
    /// the checkpoint owns the flush and the CAS failing here avoids a
    /// duplicate write.
    pub fn mark_meta_dirty(&self, st: &Arc<StreamState>) {
        if st.is_fenced() {
            st.meta_dirty.store(false, Ordering::Release);
            return;
        }
        if st
            .meta_dirty
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.meta_sweep.lock().unwrap().push(Arc::clone(st));
        }
    }

    /// Drain the pending sweep set and write each still-dirty stream's sidecar
    /// (non-durable), returning how many were written. Blocking file I/O —
    /// call from a blocking context. Errors are ignored exactly like the
    /// debounced flush ignored them (the sidecar is non-durable by contract).
    pub fn sweep_meta_once(&self) -> usize {
        let drained: Vec<Arc<StreamState>> = std::mem::take(&mut *self.meta_sweep.lock().unwrap());
        let mut n = 0;
        for st in drained {
            if st.is_fenced() {
                st.meta_dirty.store(false, Ordering::Release);
                continue;
            }
            // A hard-deleted stream's files are already unlinked — flushing
            // would resurrect its sidecar. Same `Arc` identity check as
            // delete's `remove_if`. (Soft-deleted streams stay in the map and
            // must flush: the sidecar records the `soft_deleted` flag.)
            let live = self
                .streams
                .get(&st.path)
                .is_some_and(|cur| Arc::ptr_eq(cur.value(), &st));
            if live && st.meta_dirty.swap(false, Ordering::AcqRel) {
                let _ = write_meta_sync(&st, false);
                n += 1;
            }
        }
        n
    }
}

// ---------------- offsets ----------------

pub const READ_SEQ: u64 = 0;

pub fn format_offset(bytes: u64) -> String {
    format!("{:016}_{:016}", READ_SEQ, bytes)
}

pub enum ParsedOffset {
    Start,
    Now,
    At(u64),
}

pub fn parse_offset(raw: Option<&str>) -> Result<ParsedOffset, ()> {
    match raw {
        None => Ok(ParsedOffset::Start),
        Some("-1") => Ok(ParsedOffset::Start),
        Some("now") => Ok(ParsedOffset::Now),
        Some(s) => {
            let (a, b) = s.split_once('_').ok_or(())?;
            if a.len() != 16 || b.len() != 16 {
                return Err(());
            }
            if !a.bytes().all(|c| c.is_ascii_digit()) || !b.bytes().all(|c| c.is_ascii_digit()) {
                return Err(());
            }
            let _seq: u64 = a.parse().map_err(|_| ())?;
            let bytes: u64 = b.parse().map_err(|_| ())?;
            Ok(ParsedOffset::At(bytes))
        }
    }
}

// ---------------- cursor (CDN collapsing) ----------------

/// Protocol epoch: Oct 9 2024 00:00:00 UTC, 20s intervals.
const CURSOR_EPOCH_UNIX: u64 = 1_728_432_000;
const CURSOR_INTERVAL_SECS: u64 = 20;

pub fn compute_cursor(client_cursor: Option<u64>) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let interval = now.saturating_sub(CURSOR_EPOCH_UNIX) / CURSOR_INTERVAL_SECS;
    match client_cursor {
        // Client is at/ahead of the current interval: advance by random jitter
        // (§10.1, 1–3600s i.e. 1–180 intervals) so collapsed waiters don't all
        // re-request in lockstep. Entropy from the sub-second clock (no rng dep).
        Some(c) if c >= interval => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            c + 1 + (nanos % 180) as u64
        }
        _ => interval,
    }
}

// ---------------- tiering integration tests ----------------

#[cfg(test)]
mod tier_tests {
    use super::*;
    use crate::tier::{TierConfig, TierKind};

    fn tmp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ds-tier-test-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn local_tier(dir: &std::path::Path, segment_bytes: u64) -> TierConfig {
        TierConfig {
            kind: TierKind::Local,
            segment_bytes,
            local_dir: Some(dir.join("cold")),
            ..Default::default()
        }
    }

    /// Append raw wire bytes to a stream the same way the handler does: write to
    /// the appender file, bump `written` + `tail`. (Test-only shortcut around the
    /// HTTP handler.)
    async fn append_wire(st: &Arc<StreamState>, wire: &[u8]) {
        use std::io::Write;
        let mut ap = st.appender.lock().await;
        (&*ap.file).write_all(wire).unwrap();
        ap.written += wire.len() as u64;
        let mut s = st.shared.write().unwrap();
        let tail = s.file_base + ap.written;
        s.tail = tail;
        // Test shortcut: treat the write as immediately durable/visible.
        s.durable_tail = tail;
    }

    /// Read a logical range back through the placement-aware resolver, exactly as
    /// the handler's mixed-range path does, and return the materialized bytes.
    async fn read_logical(st: &Arc<StreamState>, start: u64, end: u64) -> Vec<u8> {
        let mut slices = Vec::new();
        resolve_range(st, start, end, &mut slices);
        let mut out = Vec::new();
        for sl in slices {
            match sl {
                ResolvedSlice::Local(seg) => {
                    let b = tokio::task::spawn_blocking(move || materialize_segments(&[seg]))
                        .await
                        .unwrap();
                    out.extend_from_slice(&b);
                }
                ResolvedSlice::Remote { key, offset, len } => {
                    let bs = st.blobstore.clone().unwrap();
                    let b = bs.get_range(&key, offset, len).await.unwrap();
                    out.extend_from_slice(&b);
                }
                ResolvedSlice::Missing => panic!("test read hit a poison slice"),
            }
        }
        out
    }

    /// Test mirror of the handler gate: is `[start, end)` served entirely from
    /// local fds (the live data file and/or sealed chunk files), with no remote
    /// slice? Equivalent to `into_local_segments(resolve_range(..)).is_ok()`.
    fn all_local(st: &Arc<StreamState>, start: u64, end: u64) -> bool {
        let mut slices = Vec::new();
        resolve_range(st, start, end, &mut slices);
        into_local_segments(slices).is_ok()
    }

    #[tokio::test]
    async fn round_trip_through_cold_storage() {
        let dir = tmp_dir("roundtrip");
        let store =
            Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 64 * 1024)).unwrap());
        let cfg = StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let st = match store.create("s/cold", cfg, None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };

        // Build a deterministic payload > 2 segments.
        let total = 200 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        // Append in chunks.
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&st, chunk).await;
        }

        // Force sealing/offload.
        store.maybe_seal(&st).await;

        // The manifest should now hold remote segments covering a prefix.
        let (sealed, n_remote, n_local) = {
            let m = st.tier.manifest.lock().unwrap();
            (
                m.sealed_offset,
                m.segments.iter().filter(|s| s.remote).count(),
                m.segments.iter().filter(|s| !s.remote).count(),
            )
        };
        assert!(sealed >= 64 * 1024, "expected sealed prefix, got {sealed}");
        assert!(n_remote >= 1, "expected offloaded segments");
        assert_eq!(n_local, 0, "all sealed segments should be offloaded");

        // Full catch-up read must be byte-identical, spanning cold + hot.
        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(got, payload, "full round-trip mismatch");

        // A read spanning the hot/cold boundary returns identical bytes.
        let mid = sealed - 100;
        let got2 = read_logical(&st, mid, sealed + 100).await;
        assert_eq!(got2, payload[mid as usize..(sealed + 100) as usize]);

        // A cold (offloaded) range has a remote slice → not all-local; the hot
        // tail is served entirely from the live data file → all-local.
        assert!(!all_local(&st, 0, sealed));
        assert!(all_local(&st, sealed, total as u64));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn compaction_reclaims_live_file() {
        // With compaction on, once the reclaimable sealed prefix crosses
        // `compact_bytes` the live data file is rewritten to hold only the hot
        // tail `[sealed_offset, tail)`; reads of the full history stay exact.
        let dir = tmp_dir("compact-reclaim");
        let mut cfg = local_tier(&dir, 64 * 1024); // 64 KiB segments
        cfg.compact_bytes = 128 * 1024; // compact once ≥128 KiB is reclaimable
        let store = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
        let scfg = StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let st = match store.create("s/compact", scfg, None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };

        // 500 KiB → seals 7×64 KiB (448 KiB), leaving a 52 KiB hot tail.
        let total = 500 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&st, chunk).await;
        }

        store.maybe_seal(&st).await; // seals + offloads + compacts

        let (sealed, n_segs) = {
            let m = st.tier.manifest.lock().unwrap();
            (m.sealed_offset, m.segments.len())
        };
        let (tail, file_base) = {
            let s = st.shared.read().unwrap();
            (s.tail, s.file_base)
        };
        assert!(
            sealed >= 128 * 1024,
            "expected a reclaimable sealed prefix, got {sealed}"
        );
        assert_eq!(
            file_base, sealed,
            "file_base advanced to the sealed watermark"
        );

        let live_size = std::fs::metadata(&st.file_path).unwrap().len();
        assert_eq!(
            live_size,
            tail - sealed,
            "live file holds only the hot tail"
        );
        assert!(
            live_size < total as u64,
            "live file ({live_size}) must be smaller than the full stream ({total})"
        );

        // Full catch-up read is byte-identical across the compacted (cold) prefix
        // and the live tail.
        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(got, payload, "round-trip after compaction");

        // A read spanning the cold/hot boundary is exact.
        let mid = sealed - 100;
        let got2 = read_logical(&st, mid, sealed + 100).await;
        assert_eq!(got2, payload[mid as usize..(sealed + 100) as usize]);

        // Compaction never touches the manifest.
        assert!(n_segs >= 1, "manifest still lists the sealed segments");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn compaction_respects_threshold() {
        // Below `compact_bytes` the live file is left intact (file_base unmoved),
        // and reads remain exact — compaction is purely a reclaim, never required
        // for correctness.
        let dir = tmp_dir("compact-threshold");
        let mut cfg = local_tier(&dir, 64 * 1024);
        cfg.compact_bytes = 10 * 1024 * 1024; // 10 MiB — far above this stream
        let store = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
        let scfg = StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let st = match store.create("s/nothresh", scfg, None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };
        let total = 200 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&st, chunk).await;
        }
        store.maybe_seal(&st).await;

        let file_base = st.shared.read().unwrap().file_base;
        assert_eq!(file_base, 0, "below threshold → no compaction");
        let live_size = std::fs::metadata(&st.file_path).unwrap().len();
        assert_eq!(live_size, total as u64, "live file retains the full stream");

        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(got, payload, "reads exact without compaction");

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn octet_cfg() -> StreamConfig {
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

    #[tokio::test]
    async fn recovery_after_real_compaction() {
        // A cleanly-compacted stream reopens with the persisted file_base, the
        // compacted (small) live file, the right tail, and exact full read-back.
        let dir = tmp_dir("compact-recover");
        let total = 500 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let (sealed, tail) = {
            let mut cfg = local_tier(&dir, 64 * 1024);
            cfg.compact_bytes = 128 * 1024;
            let store = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
            let st = match store.create("s/cr", octet_cfg(), None, 0).unwrap() {
                CreateResult::Created(s) => s,
                _ => panic!("create failed"),
            };
            for chunk in payload.chunks(8 * 1024) {
                append_wire(&st, chunk).await;
            }
            store.maybe_seal(&st).await; // compacts
            let sealed = st.tier.manifest.lock().unwrap().sealed_offset;
            let tail = st.shared.read().unwrap().tail;
            (sealed, tail)
        };

        let mut cfg = local_tier(&dir, 64 * 1024);
        cfg.compact_bytes = 128 * 1024;
        let store2 = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
        let st = store2.get("s/cr").expect("stream recovered");
        let (rtail, rfb) = {
            let s = st.shared.read().unwrap();
            (s.tail, s.file_base)
        };
        assert_eq!(rtail, tail, "tail recovered");
        assert_eq!(rfb, sealed, "file_base recovered to the sealed watermark");
        let live_size = std::fs::metadata(&st.file_path).unwrap().len();
        assert_eq!(live_size, tail - sealed, "compacted live file recovered");
        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(got, payload, "post-compaction-recovery read exact");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Simulate a crash mid-compaction: persist the `pending_compaction` intent,
    /// then leave the live file either as the original full file (`simulate_renamed
    /// == false`, crash before the rename) or rewritten to just the hot tail
    /// (`true`, crash after the rename). Recovery must reconstruct the right
    /// `file_base` from `pending.tail - file_size` in both cases and read exact.
    async fn recover_with_pending_intent(tag: &str, simulate_renamed: bool) {
        let dir = tmp_dir(tag);
        let total = 300 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let (sealed, tail, file_path) = {
            let mut cfg = local_tier(&dir, 64 * 1024);
            cfg.compact_bytes = 0; // no auto-compaction; we craft the crash state
            let store = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
            let st = match store.create("s/pend", octet_cfg(), None, 0).unwrap() {
                CreateResult::Created(s) => s,
                _ => panic!("create failed"),
            };
            for chunk in payload.chunks(8 * 1024) {
                append_wire(&st, chunk).await;
            }
            store.maybe_seal(&st).await; // seals, no compaction
            let sealed = st.tier.manifest.lock().unwrap().sealed_offset;
            let tail = st.shared.read().unwrap().tail;
            // Persist the compaction intent as if a compaction had started.
            *st.compaction.lock().unwrap() = Some(PendingCompaction {
                new_file_base: sealed,
                tail,
            });
            let stc = st.clone();
            tokio::task::spawn_blocking(move || write_meta_sync(&stc, true))
                .await
                .unwrap()
                .unwrap();
            (sealed, tail, st.file_path.clone())
        };
        if simulate_renamed {
            // Crash after the rename: the live file already holds only [sealed,tail).
            let full = std::fs::read(&file_path).unwrap();
            std::fs::write(&file_path, &full[sealed as usize..]).unwrap();
        }

        let mut cfg = local_tier(&dir, 64 * 1024);
        cfg.compact_bytes = 0;
        let store2 = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
        let st = store2.get("s/pend").expect("stream recovered");
        let rtail = st.shared.read().unwrap().tail;
        assert_eq!(rtail, tail, "tail recovered to the frozen value ({tag})");
        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(got, payload, "pending-intent recovery read exact ({tag})");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn recovery_pending_intent_before_rename() {
        recover_with_pending_intent("pend-before", false).await;
    }

    #[tokio::test]
    async fn recovery_pending_intent_after_rename() {
        recover_with_pending_intent("pend-after", true).await;
    }

    /// C3 regression: under `fast`, a crash *after* the compaction intent is
    /// persisted but *before* the rename leaves the OLD live file in place with an
    /// un-fsynced (and thus possibly short) tail, while the fsynced `compact.tmp`
    /// holds the full residual `[cut, tail)`. Recovery must prefer the durable temp
    /// file — trusting `p.tail` against the short old file skews `file_base` and
    /// over-reports the tail. Asserts no offset skew: the recovered live region
    /// maps `[cut, tail)` exactly and the full logical range reads byte-identical.
    #[tokio::test]
    async fn recovery_pending_intent_prefers_fsynced_temp_when_old_file_short() {
        let dir = tmp_dir("pend-fast-short");
        let total = 300 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let (sealed, tail, file_path) = {
            let mut cfg = local_tier(&dir, 64 * 1024);
            cfg.compact_bytes = 0; // craft the crash state by hand
            let store = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
            let st = match store.create("s/pend", octet_cfg(), None, 0).unwrap() {
                CreateResult::Created(s) => s,
                _ => panic!("create failed"),
            };
            for chunk in payload.chunks(8 * 1024) {
                append_wire(&st, chunk).await;
            }
            store.maybe_seal(&st).await; // seals, no compaction
            let sealed = st.tier.manifest.lock().unwrap().sealed_offset;
            let tail = st.shared.read().unwrap().tail;
            // compact step 1: write the FULL residual [sealed, tail) to compact.tmp
            // and fsync it (the temp fsync is NOT gated by fast).
            let residual = std::fs::read(&st.file_path).unwrap()[sealed as usize..].to_vec();
            let tmp = st.file_path.with_extension("compact.tmp");
            {
                use std::io::Write;
                let mut f = std::fs::File::create(&tmp).unwrap();
                f.write_all(&residual).unwrap();
                f.sync_all().unwrap();
            }
            // compact step 2: persist the intent durably.
            *st.compaction.lock().unwrap() = Some(PendingCompaction {
                new_file_base: sealed,
                tail,
            });
            let stc = st.clone();
            tokio::task::spawn_blocking(move || write_meta_sync(&stc, true))
                .await
                .unwrap()
                .unwrap();
            (sealed, tail, st.file_path.clone())
        };
        // Crash BEFORE the rename, under fast: the OLD live file is still in
        // place but lost its un-fsynced suffix — simulate by truncating it short
        // (drop the last 16 KiB of the un-synced tail). The temp holds the truth.
        {
            let full = std::fs::read(&file_path).unwrap();
            let short = full.len() - 16 * 1024;
            std::fs::write(&file_path, &full[..short]).unwrap();
        }

        let mut cfg = local_tier(&dir, 64 * 1024);
        cfg.compact_bytes = 0;
        let store2 = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
        let st = store2.get("s/pend").expect("stream recovered");
        let (rtail, rfb) = {
            let s = st.shared.read().unwrap();
            (s.tail, s.file_base)
        };
        // No offset skew: file_base maps to the sealed watermark (the residual's
        // logical start), and the tail is the frozen full tail — both from the
        // durable temp, not the short old file.
        assert_eq!(
            rfb, sealed,
            "file_base recovered to sealed watermark, no skew"
        );
        assert_eq!(rtail, tail, "tail recovered to the frozen full value");
        let live_size = std::fs::metadata(&st.file_path).unwrap().len();
        assert_eq!(live_size, tail - sealed, "live file is the full residual");
        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(
            got, payload,
            "full read exact after fast crash-before-rename"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fork_reads_compacted_parent() {
        // A fork inherits its parent's history below the fork point. After the
        // parent is compacted (its sealed prefix dropped from the live file), the
        // fork must still read that history — resolve_range routes the parent's
        // sealed offsets to the manifest, not the (now-absent) live-file copy.
        let dir = tmp_dir("fork-compact");
        let total = 500 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let mut cfg = local_tier(&dir, 64 * 1024);
        cfg.compact_bytes = 128 * 1024;
        let store = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());

        let parent = match store.create("s/parent", octet_cfg(), None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create parent failed"),
        };
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&parent, chunk).await;
        }
        store.maybe_seal(&parent).await; // compacts the parent

        let (sealed, ptail) = {
            let m = parent.tier.manifest.lock().unwrap();
            let s = parent.shared.read().unwrap();
            (m.sealed_offset, s.tail)
        };
        assert_eq!(
            parent.shared.read().unwrap().file_base,
            sealed,
            "parent compacted"
        );

        // Fork at the parent's tail: the fork inherits all of [0, ptail).
        let fork = match store
            .create("s/fork", octet_cfg(), Some(parent.clone()), ptail)
            .unwrap()
        {
            CreateResult::Created(s) => s,
            _ => panic!("create fork failed"),
        };

        // Read the parent's full history (incl. its compacted region) via the fork.
        let got = read_logical(&fork, 0, ptail).await;
        assert_eq!(got, payload, "fork reads parent's compacted history exact");

        // A sub-range entirely inside the parent's compacted (sealed) region.
        let got2 = read_logical(&fork, 100, sealed).await;
        assert_eq!(
            got2,
            payload[100..sealed as usize],
            "fork sub-range in cold region"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: sustained concurrent appends + sealing + compaction + meta
    /// writes must not deadlock. A lock-order inversion — seal/compact held
    /// manifest.lock()→shared.read() while `write_meta_sync`'s capture held
    /// shared.read()→manifest.lock(), with appends queuing a shared writer
    /// (std RwLock is writer-preferring) — froze the server under load. This
    /// drives all three actors concurrently and must finish well under the
    /// timeout (a deadlock would hang past it). Multi-thread runtime is required
    /// to reproduce the cross-thread lock cycle.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_append_seal_compact_no_deadlock() {
        let dir = tmp_dir("no-deadlock");
        let mut cfg = local_tier(&dir, 64 * 1024);
        cfg.compact_bytes = 128 * 1024; // compact often, to exercise the swap
        let store = Arc::new(Store::new_with_tier(dir.clone(), cfg).unwrap());
        let st = match store.create("s/cc", octet_cfg(), None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };

        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            let mut handles = Vec::new();
            // Appenders: each append bumps the tail (shared writer) then drives a
            // seal/compact pass (manifest→shared).
            for _ in 0..6 {
                let s = store.clone();
                let stc = st.clone();
                handles.push(tokio::spawn(async move {
                    let body = vec![b'x'; 6 * 1024];
                    for _ in 0..120 {
                        append_wire(&stc, &body).await;
                        s.maybe_seal(&stc).await;
                    }
                }));
            }
            // Concurrent meta writer (shared→manifest), the opposite lock order.
            let stc = st.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..300 {
                    let s2 = stc.clone();
                    let _ = tokio::task::spawn_blocking(move || write_meta_sync(&s2, false)).await;
                    tokio::task::yield_now().await;
                }
            }));
            for h in handles {
                let _ = h.await;
            }
        })
        .await;

        assert!(
            outcome.is_ok(),
            "concurrent append + seal + compact + meta deadlocked (lock-order regression)"
        );

        // Sanity: the stream is intact and fully readable end to end.
        let tail = st.shared.read().unwrap().tail;
        let got = read_logical(&st, 0, tail).await;
        assert_eq!(
            got.len() as u64,
            tail,
            "full read-back length after concurrent load"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A BlobStore whose uploads always fail — used to leave a sealed segment in
    /// the `Local` (not-yet-offloaded) state.
    struct FailingBlobStore;
    impl crate::blobstore::BlobStore for FailingBlobStore {
        fn put<'a>(
            &'a self,
            _key: &'a str,
            _body: bytes::Bytes,
        ) -> crate::blobstore::BoxFuture<'a, std::io::Result<()>> {
            Box::pin(async { Err(std::io::Error::other("offload disabled (test)")) })
        }
        fn get_range<'a>(
            &'a self,
            _key: &'a str,
            _start: u64,
            _len: u64,
        ) -> crate::blobstore::BoxFuture<'a, std::io::Result<bytes::Bytes>> {
            Box::pin(async { Err(std::io::Error::other("no remote (test)")) })
        }
        fn head<'a>(
            &'a self,
            _key: &'a str,
        ) -> crate::blobstore::BoxFuture<'a, std::io::Result<Option<u64>>> {
            Box::pin(async { Ok(None) })
        }
        fn delete<'a>(
            &'a self,
            _key: &'a str,
        ) -> crate::blobstore::BoxFuture<'a, std::io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn sealed_local_offload_failure_is_readable() {
        // Offload-failure resilience: a sealed segment whose upload fails stays
        // `Local` in the manifest (its bytes in the staged chunk file) and must
        // remain fully readable from local fds — never erroring or reaching for a
        // remote object that was never written. resolve_range routes it to the
        // chunk file, so the range is all-local and reads back byte-identical.
        let dir = tmp_dir("sealed-local");
        let mut store = Store::new_with_tier(dir.clone(), local_tier(&dir, 64 * 1024)).unwrap();
        store.blobstore = Some(Arc::new(FailingBlobStore)); // offload fails → stays Local
        let store = Arc::new(store);
        let cfg = StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let st = match store.create("s/sl", cfg, None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };
        let total = 200 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&st, chunk).await;
        }
        // Seals the first segment to a chunk file; offload fails → it stays Local.
        store.maybe_seal(&st).await;

        let (sealed, n_local, n_remote) = {
            let m = st.tier.manifest.lock().unwrap();
            (
                m.sealed_offset,
                m.segments.iter().filter(|s| !s.remote).count(),
                m.segments.iter().filter(|s| s.remote).count(),
            )
        };
        assert!(sealed > 0, "expected a sealed prefix");
        assert!(n_local > 0, "offload failed → segment should remain Local");
        assert_eq!(n_remote, 0, "no segment should be remote (offload failed)");

        // A failed-offload sealed segment is served entirely from local fds (its
        // chunk file): the range is all-local with no remote slice to fetch.
        assert!(
            all_local(&st, st.base_offset, sealed),
            "a sealed Local segment is served from its chunk file (all-local)"
        );
        // And it reads back byte-identical (from the chunk file, not a missing
        // remote object).
        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(
            got, payload,
            "sealed-Local read must return the staged bytes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn json_seal_lands_on_value_boundary() {
        let dir = tmp_dir("json");
        // Small segment so a handful of values trigger a seal.
        let store = Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 1024)).unwrap());
        let cfg = StreamConfig {
            content_type: "application/json".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let st = match store.create("s/json", cfg, None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!(),
        };
        assert!(st.is_json);

        // Each value contains commas and brackets INSIDE strings, which must not
        // be treated as boundaries.
        let mut wire = Vec::new();
        let mut values: Vec<String> = Vec::new();
        for i in 0..200 {
            let v = format!(r#"{{"i":{i},"s":"a,b[c]{{d}}","arr":[1,2,3]}}"#);
            wire.extend_from_slice(v.as_bytes());
            wire.push(b',');
            values.push(v);
        }
        for chunk in wire.chunks(128) {
            append_wire(&st, chunk).await;
        }
        store.maybe_seal(&st).await;

        let sealed = st.tier.manifest.lock().unwrap().sealed_offset;
        assert!(sealed > 0, "expected JSON stream to seal");
        // The sealed prefix must end exactly on a value boundary (a `,` right
        // after a complete value) — i.e. wire[sealed-1] == b',' and the prefix
        // parses as a whole number of values.
        assert_eq!(wire[sealed as usize - 1], b',');

        // Reconstruct the sealed prefix and confirm it is exactly the first K
        // complete values + trailing comma.
        let got = read_logical(&st, 0, sealed).await;
        assert_eq!(got, &wire[..sealed as usize]);
        // Wrap as [ … ] (drop trailing comma) and parse as JSON to prove it is a
        // valid, complete array of values.
        let inner = &got[..got.len() - 1];
        let json = format!("[{}]", String::from_utf8_lossy(inner));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(!parsed.as_array().unwrap().is_empty());

        // Full read is byte-identical.
        let full = read_logical(&st, 0, wire.len() as u64).await;
        assert_eq!(full, wire);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reads_during_seal_are_consistent() {
        let dir = tmp_dir("concurrent");
        let store =
            Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 32 * 1024)).unwrap());
        let cfg = StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds: None,
            expires_at: None,
            expires_at_raw: None,
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        };
        let st = match store.create("s/conc", cfg, None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!(),
        };
        let total = 256 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&st, chunk).await;
        }

        // Launch readers concurrently with the sealing pass; none must see torn
        // bytes regardless of unlink/hole-punch timing.
        let st2 = st.clone();
        let pl = payload.clone();
        let reader = tokio::spawn(async move {
            for _ in 0..50 {
                let got = read_logical(&st2, 0, total as u64).await;
                assert_eq!(got, pl, "torn read during seal");
                tokio::task::yield_now().await;
            }
        });
        store.maybe_seal(&st).await;
        reader.await.unwrap();

        // After seal, read again — fully served from cold + hot.
        let got = read_logical(&st, 0, total as u64).await;
        assert_eq!(got, payload);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn manifest_survives_recovery() {
        let dir = tmp_dir("recovery");
        {
            let store =
                Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 64 * 1024)).unwrap());
            let cfg = StreamConfig {
                content_type: "application/octet-stream".into(),
                ttl_seconds: None,
                expires_at: None,
                expires_at_raw: None,
                create_closed: false,
                forked_from: None,
                fork_offset_raw: None,
                fork_sub_offset: None,
            };
            let st = match store.create("s/rec", cfg, None, 0).unwrap() {
                CreateResult::Created(s) => s,
                _ => panic!(),
            };
            let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
            for chunk in payload.chunks(8 * 1024) {
                append_wire(&st, chunk).await;
            }
            store.maybe_seal(&st).await;
        }
        // Re-open the store; the manifest must rehydrate from the sidecar and
        // cold reads must still work.
        let store2 =
            Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 64 * 1024)).unwrap());
        let st = store2.get("s/rec").expect("stream recovered");
        let sealed = st.tier.manifest.lock().unwrap().sealed_offset;
        assert!(sealed >= 64 * 1024, "manifest not recovered");
        let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let got = read_logical(&st, 0, payload.len() as u64).await;
        assert_eq!(got, payload, "post-recovery cold read mismatch");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression for the WAL read-before-durable bug: a reader (via `tail()`)
    /// must observe bytes only once they are DURABLE. During the WAL-fsync window
    /// the writer tail `s.tail` runs ahead of the reader-observable `durable_tail`
    /// (set in `write_wire` vs published in `publish_durable_tail` after the WAL
    /// `fdatasync`). `tail()` must report the durable frontier so a live/catch-up
    /// reader never observes (and acts on) bytes a crash could roll back
    /// (PROTOCOL.md §4.1).
    #[tokio::test]
    async fn reader_tail_tracks_durable_not_writer_tail() {
        let dir = tmp_dir("durable-tail");
        let store =
            Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 64 * 1024)).unwrap());
        let st = match store.create("s/dur", octet_cfg(), None, 0).unwrap() {
            CreateResult::Created(st) => st,
            _ => panic!("expected created"),
        };

        // Fresh stream: writer and durable tails agree at 0.
        assert_eq!(st.tail().bytes, 0);

        // Simulate `write_wire`: bytes hit the page cache and the WRITER tail
        // advances, but durability has NOT been published (WAL fsync pending).
        let wire = b"hello world";
        {
            use std::io::Write;
            let mut ap = st.appender.lock().await;
            (&*ap.file).write_all(wire).unwrap();
            ap.written += wire.len() as u64;
            let mut s = st.shared.write().unwrap();
            s.tail = s.file_base + ap.written;
            // `durable_tail` intentionally NOT advanced — fsync still pending.
        }

        // A reader must NOT observe the not-yet-durable bytes.
        assert_eq!(
            st.tail().bytes,
            0,
            "reader observed bytes before they were durable"
        );

        // Simulate `publish_durable_tail` after the WAL fsync succeeds.
        {
            let mut s = st.shared.write().unwrap();
            s.durable_tail = s.tail;
        }

        // Durable now → reader-visible.
        assert_eq!(st.tail().bytes, wire.len() as u64);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression for the hard-delete GC race: after a hard delete, every
    /// offloaded remote object (and any staged local chunk) backing the stream
    /// must be reclaimed — no orphans. Guards `gc_remote_segments` and its
    /// `deleted`-flag coordination with seal/offload.
    #[tokio::test]
    async fn hard_delete_reclaims_offloaded_segments() {
        fn count_files(root: &std::path::Path) -> usize {
            let mut n = 0;
            if let Ok(rd) = std::fs::read_dir(root) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        n += count_files(&p);
                    } else {
                        n += 1;
                    }
                }
            }
            n
        }

        let dir = tmp_dir("gc-reclaim");
        let store =
            Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 64 * 1024)).unwrap());
        let st = match store.create("s/gc", octet_cfg(), None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };

        // Append > 2 segments and offload them to the (local) remote tier.
        let total = 200 * 1024usize;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&st, chunk).await;
        }
        store.maybe_seal(&st).await;

        let cold = dir.join("cold");
        assert!(
            count_files(&cold) >= 1,
            "expected offloaded remote objects before delete"
        );

        // Hard delete (ref_count == 0 → hard delete → gc_remote_segments).
        store.delete_or_soft_delete(&st);

        // The GC runs as a detached task — wait for it to reclaim everything.
        let mut waited = 0;
        while count_files(&cold) > 0 && waited < 300 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            waited += 1;
        }
        assert_eq!(
            count_files(&cold),
            0,
            "orphaned remote objects after hard delete"
        );
        assert_eq!(
            count_files(&dir.join("segments")),
            0,
            "leaked local chunk files after hard delete"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Once a stream is hard-deleted (`deleted` set), a seal pass must bail
    /// without staging new chunk files or manifest entries — otherwise it would
    /// race the GC reclaim and leak. (On the pre-fix code, with no `deleted`
    /// flag, `maybe_seal` would proceed and stage segments here.)
    #[tokio::test]
    async fn seal_bails_after_hard_delete_flag() {
        let dir = tmp_dir("gc-seal-bail");
        let store =
            Arc::new(Store::new_with_tier(dir.clone(), local_tier(&dir, 64 * 1024)).unwrap());
        let st = match store.create("s/gcseal", octet_cfg(), None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        };
        // Enough unsealed data for several seals.
        let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        for chunk in payload.chunks(8 * 1024) {
            append_wire(&st, chunk).await;
        }

        // Hard delete arrived before the seal pass runs.
        st.tier.manifest.lock().unwrap().deleted = true;

        // The seal pass must be a no-op now.
        store.maybe_seal(&st).await;

        {
            let m = st.tier.manifest.lock().unwrap();
            assert_eq!(m.segments.len(), 0, "seal staged segments despite deleted");
            assert_eq!(
                m.sealed_offset, 0,
                "seal advanced watermark despite deleted"
            );
        }
        let seg_files = std::fs::read_dir(dir.join("segments"))
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(seg_files, 0, "seal staged chunk files despite deleted");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------- batched meta sweep tests (#4691) ----------------

#[cfg(test)]
mod meta_sweep_tests {
    use super::*;
    use crate::tier::TierConfig;

    // DELETE_FAULT is a process-global test hook. Serialize the two tests that
    // manipulate it so a parallel test cannot clear another test's injected
    // failure between the operation and its publication-order assertion.
    static DELETE_FAULT_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    fn tmp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ds-meta-sweep-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn octet_cfg() -> StreamConfig {
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

    fn create(store: &Store, path: &str) -> Arc<StreamState> {
        match store.create(path, octet_cfg(), None, 0).unwrap() {
            CreateResult::Created(s) => s,
            _ => panic!("create failed"),
        }
    }

    fn disk_meta(st: &StreamState) -> Meta {
        serde_json::from_slice(&std::fs::read(meta_path(&st.file_path)).unwrap()).unwrap()
    }

    /// Marking is idempotent while a flush is pending (one sweep entry per
    /// stream per cycle), the sweep persists the pending state, and a clean
    /// sweep is a no-op.
    #[tokio::test]
    async fn mark_dedupes_and_sweep_flushes() {
        let dir = tmp_dir("flush");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let st = create(&store, "s");

        st.shared.write().unwrap().producers.insert(
            "p1".into(),
            ProducerState {
                epoch: 1,
                last_seq: 3,
            },
        );
        store.mark_meta_dirty(&st);
        store.mark_meta_dirty(&st); // second mark while pending: deduped

        assert!(
            !disk_meta(&st).producers.contains_key("p1"),
            "marking alone must not write the sidecar"
        );
        assert_eq!(store.sweep_meta_once(), 1, "one dirty stream, one flush");
        let meta = disk_meta(&st);
        let p = meta
            .producers
            .get("p1")
            .expect("sweep persists the pending producer state");
        assert_eq!((p.epoch, p.last_seq), (1, 3));
        assert!(
            !st.meta_dirty.load(Ordering::Acquire),
            "sweep clears the dirty flag"
        );
        assert_eq!(store.sweep_meta_once(), 0, "nothing left to sweep");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stream hard-deleted after being marked dirty must NOT get its sidecar
    /// resurrected by a later sweep (the file unlinks already happened).
    #[tokio::test]
    async fn sweep_skips_hard_deleted_stream() {
        let dir = tmp_dir("deleted");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let st = create(&store, "s");

        store.mark_meta_dirty(&st);
        store.delete_or_soft_delete_durable(&st).unwrap();
        assert!(
            !meta_path(&st.file_path).exists(),
            "hard delete unlinked the sidecar"
        );

        assert_eq!(store.sweep_meta_once(), 0, "deleted stream is skipped");
        assert!(
            !meta_path(&st.file_path).exists(),
            "sweep must not resurrect a deleted stream's sidecar"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_delete_faults_preserve_inventory_publication_order() {
        let _fault_guard = DELETE_FAULT_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tmp_dir("inventory-delete-fault");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let soft = create(&store, "soft");
        soft.shared.write().unwrap().ref_count = 1;
        DELETE_FAULT.store(1, Ordering::Relaxed);
        assert!(store.delete_or_soft_delete_durable(&soft).is_err());
        DELETE_FAULT.store(0, Ordering::Relaxed);
        let (_, entries, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(entries
            .iter()
            .any(|entry| entry.path == "soft" && !entry.deleted));
        assert!(!soft.shared.read().unwrap().soft_deleted);

        let hard = create(&store, "hard");
        DELETE_FAULT.store(2, Ordering::Relaxed);
        assert!(store.delete_or_soft_delete_durable(&hard).is_err());
        let (_, entries, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(entries.iter().any(|entry| entry.path == "hard"));
        DELETE_FAULT.store(0, Ordering::Relaxed);
        store.delete_or_soft_delete_durable(&hard).unwrap();
        let (_, entries, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(!entries.iter().any(|entry| entry.path == "hard"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expiry_keeps_inventory_until_durable_unlink_succeeds() {
        let _fault_guard = DELETE_FAULT_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tmp_dir("expiry-delete-fault");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let mut config = octet_cfg();
        config.ttl_seconds = Some(1);
        let st = match store.create("expired", config, None, 0).unwrap() {
            CreateResult::Created(st) => st,
            _ => panic!(),
        };
        st.shared.write().unwrap().last_access = SystemTime::now() - Duration::from_secs(2);
        DELETE_FAULT.store(2, Ordering::Relaxed);
        assert!(store.get("expired").is_none());
        let (_, entries, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(entries.iter().any(|entry| entry.path == "expired"));
        DELETE_FAULT.store(0, Ordering::Relaxed);
        assert!(store.get("expired").is_none());
        let (_, entries, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(!entries.iter().any(|entry| entry.path == "expired"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------- expiration reaper tests ----------------

#[cfg(test)]
mod expiration_reaper_tests {
    use super::*;
    use crate::tier::TierConfig;

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ds-expiry-reaper-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn config(ttl_seconds: Option<u64>, expires_at: Option<SystemTime>) -> StreamConfig {
        StreamConfig {
            content_type: "application/octet-stream".into(),
            ttl_seconds,
            expires_at,
            expires_at_raw: expires_at.map(|_| "test-time".into()),
            create_closed: false,
            forked_from: None,
            fork_offset_raw: None,
            fork_sub_offset: None,
        }
    }

    fn create(
        store: &Store,
        path: &str,
        ttl_seconds: Option<u64>,
        expires_at: Option<SystemTime>,
    ) -> Arc<StreamState> {
        match store
            .create(path, config(ttl_seconds, expires_at), None, 0)
            .unwrap()
        {
            CreateResult::Created(st) => st,
            _ => panic!("create failed"),
        }
    }

    #[test]
    fn canonical_deadline_is_strict_and_overflow_safe() {
        let dir = tmp_dir("deadlines");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let base = UNIX_EPOCH + Duration::from_secs(10);

        let ttl = create(&store, "ttl", Some(5), None);
        ttl.shared.write().unwrap().last_access = base;
        assert_eq!(ttl.expiry_deadline(), Some(base + Duration::from_secs(5)));
        assert!(!ttl.is_expired_at(base + Duration::from_secs(5)));
        assert!(ttl.is_expired_at(base + Duration::from_secs(5) + Duration::from_nanos(1)));

        let absolute = create(&store, "absolute", None, Some(base));
        absolute.shared.write().unwrap().last_access = base + Duration::from_secs(100);
        assert_eq!(absolute.expiry_deadline(), Some(base));
        assert!(!absolute.is_expired_at(base));
        assert!(absolute.is_expired_at(base + Duration::from_nanos(1)));

        let before_epoch = UNIX_EPOCH - Duration::from_secs(10);
        let ancient = create(&store, "ancient", None, Some(before_epoch));
        assert!(ancient.is_expired_at(UNIX_EPOCH - Duration::from_secs(9)));

        let huge = create(&store, "huge", Some(u64::MAX), None);
        huge.shared.write().unwrap().last_access = UNIX_EPOCH + Duration::from_secs(1);
        assert_eq!(huge.expiry_deadline(), None);
        assert!(!huge.is_expired_at(SystemTime::now()));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn expiring_index_is_exact_and_scans_in_bounded_round_robin_pages() {
        let dir = tmp_dir("index");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let permanent = create(&store, "permanent", None, None);
        let a = create(&store, "a", Some(1), None);
        let b = create(&store, "b", None, Some(now - Duration::from_secs(1)));
        let c = create(&store, "c", Some(1), None);
        a.shared.write().unwrap().last_access = now - Duration::from_secs(2);
        c.shared.write().unwrap().last_access = now - Duration::from_secs(2);

        assert_eq!(store.expiring_stream_count(), 3);
        for _ in 0..100 {
            assert!(a.touch_if_live_at(now - Duration::from_secs(2)));
        }
        assert_eq!(
            store.expiring_stream_count(),
            3,
            "touches never grow the index"
        );

        let mut cursor = ExpiryScanCursor::default();
        let first = store.scan_expiring(&mut cursor, 2, now);
        assert_eq!(first.checked, 2);
        assert!(first.due.len() <= 2);
        if let Some(candidate) = first.due.first() {
            assert!(candidate.try_mark_queued());
            assert!(
                !candidate.try_mark_queued(),
                "queue admission is deduplicated"
            );
            candidate.clear_queued();
        }
        let second = store.scan_expiring(&mut cursor, 2, now);
        assert!(second.checked <= 2);
        assert!(second.completed_pass);
        let seen: HashSet<_> = first
            .due
            .iter()
            .chain(second.due.iter())
            .map(ExpiryCandidate::stream_id)
            .collect();
        assert_eq!(seen, HashSet::from([a.id, b.id, c.id]));
        assert!(!seen.contains(&permanent.id));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lazy_expiry_and_retirement_remove_the_same_index_entry() {
        let dir = tmp_dir("lazy");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let st = create(&store, "lazy", Some(1), None);
        let now = UNIX_EPOCH + Duration::from_secs(100);
        st.shared.write().unwrap().last_access = now - Duration::from_secs(2);
        assert_eq!(store.expiring_stream_count(), 1);

        assert!(store.get_at("lazy", now).is_none());
        assert!(st.is_fenced());
        assert_eq!(store.expiring_stream_count(), 0);
        assert!(!st.file_path.exists());
        assert!(!meta_path(&st.file_path).exists());
        write_meta_sync(&st, false).unwrap();
        assert!(
            !meta_path(&st.file_path).exists(),
            "a deferred writer cannot resurrect sidecar after the fence"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lookup_fence_winner_immediately_publishes_sticky_deletion() {
        let dir = tmp_dir("lookup-fence-wake");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let st = create(&store, "stream", None, Some(now - Duration::from_secs(1)));
        let mut deleted = st.subscribe_deleted();
        let mut tail = st.tail_tx.subscribe();
        assert!(!*deleted.borrow_and_update());
        let _ = tail.borrow_and_update();

        assert!(matches!(
            store.lookup_at("stream", now, false),
            StreamLookup::Expired(_)
        ));
        assert!(st.is_fenced());
        assert!(
            *deleted.borrow_and_update(),
            "lookup must publish sticky deletion before paced retirement admission"
        );
        assert!(
            tail.has_changed().unwrap(),
            "lookup must also wake tail-based long polls"
        );

        // A lookup that only observes an existing fence is not the transition
        // winner and need not publish another wake.
        let _ = tail.borrow_and_update();
        assert!(matches!(
            store.lookup_at("stream", now, false),
            StreamLookup::Expired(_)
        ));
        assert!(!tail.has_changed().unwrap());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn prepare_fence_wakes_before_waiting_for_inflight_append_drain() {
        let dir = tmp_dir("prepare-fence-wake");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let base = UNIX_EPOCH + Duration::from_secs(100);
        let st = create(&store, "stream", Some(1), None);
        st.shared.write().unwrap().last_access = base;
        let appender = st.appender.lock().await;
        let append = st.begin_append_at(base).unwrap();
        drop(appender);
        let candidate = store.candidate_for(&st);
        let mut deleted = st.subscribe_deleted();

        let mut prepare =
            Box::pin(store.prepare_expiry_retirement(&candidate, base + Duration::from_secs(2)));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut prepare)
                .await
                .is_err(),
            "prepare must remain pending while the append guard is live"
        );
        assert!(st.is_fenced());
        assert!(
            *deleted.borrow_and_update(),
            "the fence wake must not wait for append drain or paced cleanup"
        );

        drop(append);
        assert_eq!(prepare.await, PrepareRetirement::Ready);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn expiry_fence_waits_for_full_append_guard_and_blocks_publication() {
        let dir = tmp_dir("append-race");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let deadline = UNIX_EPOCH + Duration::from_secs(100);
        let st = create(&store, "append-race", None, Some(deadline));

        let appender = st.appender.lock().await;
        let append = st
            .begin_append_at(deadline)
            .expect("append starts at the exact live boundary");
        drop(appender);

        let mut cursor = ExpiryScanCursor::default();
        let candidate = store
            .scan_expiring(&mut cursor, 1, deadline + Duration::from_nanos(1))
            .due
            .pop()
            .unwrap();
        let store2 = store.clone();
        let fence = tokio::spawn(async move {
            store2
                .prepare_expiry_retirement(&candidate, deadline + Duration::from_nanos(1))
                .await
        });

        while !st.is_fenced() {
            tokio::task::yield_now().await;
        }
        assert!(
            !fence.is_finished(),
            "retirement waits for the ack-path guard"
        );
        assert!(
            !append.may_publish(),
            "a fenced append cannot publish or acknowledge"
        );
        drop(append);
        assert_eq!(fence.await.unwrap(), PrepareRetirement::Ready);
        assert!(
            *st.subscribe_deleted().borrow(),
            "deletion wake remains sticky for late subscribers"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn renewed_and_stale_candidates_cannot_retire_the_wrong_incarnation() {
        let dir = tmp_dir("identity");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let old = create(&store, "same", Some(10), None);
        old.shared.write().unwrap().last_access = now - Duration::from_secs(11);
        let mut cursor = ExpiryScanCursor::default();
        let candidate = store.scan_expiring(&mut cursor, 1, now).due.pop().unwrap();

        assert!(old.touch_if_live_at(now - Duration::from_secs(1)));
        assert_eq!(
            store.prepare_expiry_retirement(&candidate, now).await,
            PrepareRetirement::Renewed
        );
        assert!(!old.is_fenced());

        old.shared.write().unwrap().last_access = now - Duration::from_secs(11);
        let mut cursor = ExpiryScanCursor::default();
        let stale = store.scan_expiring(&mut cursor, 1, now).due.pop().unwrap();
        store.streams.remove("same");
        let replacement = create(&store, "same", None, None);
        assert_eq!(
            store.prepare_expiry_retirement(&stale, now).await,
            PrepareRetirement::Stale
        );
        assert!(!replacement.is_fenced());
        let (_, inventory, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(inventory.iter().any(|entry| entry.path == "same"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn expiring_fork_parent_soft_deletes_and_leaves_child_live() {
        let dir = tmp_dir("fork");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let parent = create(&store, "parent", Some(1), None);
        let child = match store
            .create("child", config(None, None), Some(parent.clone()), 0)
            .unwrap()
        {
            CreateResult::Created(st) => st,
            _ => panic!("fork create failed"),
        };
        parent.shared.write().unwrap().last_access = now - Duration::from_secs(2);
        let mut cursor = ExpiryScanCursor::default();
        let candidate = store.scan_expiring(&mut cursor, 1, now).due.pop().unwrap();
        assert_eq!(
            store.prepare_expiry_retirement(&candidate, now).await,
            PrepareRetirement::Ready
        );
        assert_eq!(
            store
                .finish_retirement(&candidate, RetirementDurability::Expiry)
                .await
                .unwrap()
                .outcome,
            RetirementOutcome::SoftDeleted
        );
        assert!(parent.shared.read().unwrap().soft_deleted);
        assert!(parent.file_path.exists());
        assert!(store.get_at("child", now).is_some());
        assert_eq!(store.expiring_stream_count(), 0);

        store
            .delete_or_soft_delete_durable(&child)
            .expect("deleting final child collects parent");
        assert!(!parent.file_path.exists());
        assert!(!meta_path(&parent.file_path).exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn expired_create_keeps_old_incarnation_until_coordinated_finish() {
        let dir = tmp_dir("create-expired");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let old = create(&store, "same", Some(1), None);
        old.shared.write().unwrap().last_access = SystemTime::now() - Duration::from_secs(2);

        let candidate = match store.create("same", config(None, None), None, 0).unwrap() {
            CreateResult::Expired(candidate) => candidate,
            _ => panic!("expired path must remain coordinated, not be recreated inline"),
        };
        assert_eq!(candidate.stream_id(), old.id);
        assert!(store
            .streams
            .get("same")
            .is_some_and(|current| Arc::ptr_eq(current.value(), &old)));

        assert_eq!(
            store
                .prepare_expiry_retirement(&candidate, SystemTime::now())
                .await,
            PrepareRetirement::Ready
        );
        assert_eq!(
            store
                .finish_retirement(&candidate, RetirementDurability::Expiry)
                .await
                .unwrap()
                .outcome,
            RetirementOutcome::Reaped
        );
        let replacement = create(&store, "same", None, None);
        assert_ne!(replacement.id, old.id);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn hard_retirement_reports_unlinked_local_bytes() {
        use std::io::Write;

        let dir = tmp_dir("reclaimed-bytes");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let st = create(&store, "bytes", None, None);
        {
            let mut appender = st.appender.lock().await;
            (&*appender.file).write_all(b"reclaimed").unwrap();
            appender.written = 9;
            let mut shared = st.shared.write().unwrap();
            shared.tail = 9;
            shared.durable_tail = 9;
        }
        write_meta_sync(&st, true).unwrap();
        let expected = std::fs::metadata(&st.file_path).unwrap().len()
            + std::fs::metadata(meta_path(&st.file_path)).unwrap().len();

        assert_eq!(store.prepare_delete(&st).await, PrepareRetirement::Ready);
        let step = store
            .finish_retirement(&store.candidate_for(&st), RetirementDurability::Explicit)
            .await
            .unwrap();
        assert_eq!(step.outcome, RetirementOutcome::Reaped);
        assert_eq!(step.reclaimed_local_bytes, expected);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn recovered_soft_parent_zero_transition_is_durable_and_pageable() {
        let dir = tmp_dir("recovered-soft-parent");
        let parent_file;
        let child_file;

        {
            let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
            let parent = create(&store, "parent", None, None);
            let mut child_config = config(None, None);
            child_config.forked_from = Some("parent".into());
            child_config.fork_offset_raw = Some("0".into());
            let child = match store
                .create("child", child_config, Some(parent.clone()), 0)
                .unwrap()
            {
                CreateResult::Created(st) => st,
                _ => panic!("fork create failed"),
            };
            parent_file = parent.file_path.clone();
            child_file = child.file_path.clone();

            assert_eq!(
                store.prepare_delete(&parent).await,
                PrepareRetirement::Ready
            );
            let step = store
                .finish_retirement(
                    &store.candidate_for(&parent),
                    RetirementDurability::Explicit,
                )
                .await
                .unwrap();
            assert_eq!(step.outcome, RetirementOutcome::SoftDeleted);
            assert!(step.cascade.is_none());
        }

        {
            let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
            let parent = store.streams.get("parent").unwrap().clone();
            let child = store.streams.get("child").unwrap().clone();
            assert!(parent.is_fenced(), "recovered tombstones stay fenced");
            assert_eq!(parent.shared.read().unwrap().ref_count, 1);

            assert_eq!(store.prepare_delete(&child).await, PrepareRetirement::Ready);
            let step = store
                .finish_retirement(&store.candidate_for(&child), RetirementDurability::Expiry)
                .await
                .unwrap();
            assert_eq!(step.outcome, RetirementOutcome::Reaped);
            let cascade = step.cascade.expect("last child releases soft parent");
            assert_eq!(cascade.stream_id(), parent.id);

            let meta: Meta = serde_json::from_slice(
                &std::fs::read(meta_path(&parent_file)).expect("parent sidecar remains"),
            )
            .unwrap();
            assert!(meta.soft_deleted);
            assert_eq!(
                meta.ref_count, 0,
                "the zero transition is durable before cascade cleanup"
            );
        }

        // Simulate a crash between the separately paced child and parent steps.
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let parent = store.streams.get("parent").unwrap().clone();
        assert!(parent.is_fenced());
        assert_eq!(parent.shared.read().unwrap().ref_count, 0);
        let mut cursor = ExpiryScanCursor::default();
        let page = store.scan_recovered_retirements(&mut cursor, 1);
        assert_eq!(page.checked, 1);
        assert!(page.completed_pass);
        assert_eq!(store.recovered_retirement_count(), 1);
        let candidate = page.due.into_iter().next().expect("recovered cleanup seed");
        assert_eq!(
            store
                .prepare_expiry_retirement(&candidate, SystemTime::now())
                .await,
            PrepareRetirement::Ready
        );
        let step = store
            .finish_retirement(&candidate, RetirementDurability::Expiry)
            .await
            .unwrap();
        assert_eq!(step.outcome, RetirementOutcome::Reaped);
        assert!(step.cascade.is_none());
        assert_eq!(store.recovered_retirement_count(), 0);
        assert!(!parent_file.exists());
        assert!(!meta_path(&parent_file).exists());
        assert!(!child_file.exists());
        assert!(!meta_path(&child_file).exists());
        assert!(!store.streams.contains_key("parent"));
        assert!(!store.streams.contains_key("child"));
        let (_, inventory, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(inventory.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn recovery_reconciles_a_soft_parents_stale_ref_after_child_unlink_crash() {
        let dir = tmp_dir("recovered-soft-parent-stale-ref");
        let parent_file;
        let child_file;

        {
            let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
            let parent = create(&store, "parent", None, None);
            let mut child_config = config(None, None);
            child_config.forked_from = Some("parent".into());
            child_config.fork_offset_raw = Some("0".into());
            let child = match store
                .create("child", child_config, Some(parent.clone()), 0)
                .unwrap()
            {
                CreateResult::Created(st) => st,
                _ => panic!("fork create failed"),
            };
            parent_file = parent.file_path.clone();
            child_file = child.file_path.clone();

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
            assert_eq!(parent.shared.read().unwrap().ref_count, 1);

            // Exact crash image: the last child's data and sidecar unlinks are
            // directory-durable, but the parent still claims the old refcount.
            std::fs::remove_file(meta_path(&child_file)).unwrap();
            std::fs::remove_file(&child_file).unwrap();
            fsync_parent_dir(&child_file).unwrap();
            let disk_parent: Meta = serde_json::from_slice(
                &std::fs::read(meta_path(&parent_file)).expect("parent sidecar remains"),
            )
            .unwrap();
            assert!(disk_parent.soft_deleted);
            assert_eq!(disk_parent.ref_count, 1);
        }

        // Boot must derive references from recovered child->parent edges, make
        // the zero transition durable, and seed bounded cleanup without unlinking.
        {
            let recovered = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
            let parent = recovered.streams.get("parent").unwrap().clone();
            assert!(parent.is_fenced());
            assert_eq!(parent.shared.read().unwrap().ref_count, 0);
            assert!(!recovered.streams.contains_key("child"));
            assert_eq!(recovered.recovered_retirement_count(), 1);
            assert!(parent_file.exists(), "boot cleanup must remain bounded");
            let disk_parent: Meta = serde_json::from_slice(
                &std::fs::read(meta_path(&parent_file)).expect("parent sidecar remains"),
            )
            .unwrap();
            assert_eq!(
                disk_parent.ref_count, 0,
                "authoritative zero must survive a second crash before admission"
            );
        }

        let recovered = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let parent = recovered.streams.get("parent").unwrap().clone();
        let mut cursor = ExpiryScanCursor::default();
        let candidate = recovered
            .scan_recovered_retirements(&mut cursor, 1)
            .due
            .into_iter()
            .next()
            .expect("reconciled tombstone is pageably collectible");
        assert_eq!(
            recovered
                .prepare_expiry_retirement(&candidate, SystemTime::now())
                .await,
            PrepareRetirement::Ready
        );
        assert_eq!(
            recovered
                .finish_retirement(&candidate, RetirementDurability::Expiry)
                .await
                .unwrap()
                .outcome,
            RetirementOutcome::Reaped
        );
        assert!(!parent_file.exists());
        assert!(!meta_path(&parent_file).exists());
        assert!(!child_file.exists());
        assert!(!meta_path(&child_file).exists());
        assert!(!recovered.streams.contains_key("parent"));
        assert!(!recovered.streams.contains_key("child"));
        assert_eq!(recovered.recovered_retirement_count(), 0);
        let (_, inventory, _) = recovered.inventory_page(None, None, 10).unwrap();
        assert!(inventory.iter().all(|entry| entry.stream_id != parent.id));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_raises_a_stale_parent_undercount_from_actual_child_edges() {
        let dir = tmp_dir("recovered-parent-undercount");
        let parent_file;
        {
            let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
            let parent = create(&store, "parent", None, None);
            let mut child_config = config(None, None);
            child_config.forked_from = Some("parent".into());
            child_config.fork_offset_raw = Some("0".into());
            assert!(matches!(
                store.create("child", child_config, Some(parent.clone()), 0),
                Ok(CreateResult::Created(_))
            ));
            parent_file = parent.file_path.clone();
        }

        let sidecar = meta_path(&parent_file);
        let mut stale: Meta = serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        stale.ref_count = 0;
        std::fs::write(&sidecar, serde_json::to_vec(&stale).unwrap()).unwrap();
        File::open(&sidecar).unwrap().sync_all().unwrap();
        fsync_parent_dir(&sidecar).unwrap();

        let recovered = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let parent = recovered.streams.get("parent").unwrap().clone();
        assert_eq!(parent.shared.read().unwrap().ref_count, 1);
        let durable: Meta = serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(durable.ref_count, 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parked_corrupt_child_quarantine_survives_a_second_boot() {
        let dir = tmp_dir("persistent-corrupt-child-quarantine");
        let parent_file;
        let child_file;
        {
            let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
            let parent = create(&store, "parent", None, None);
            let mut child_config = config(None, None);
            child_config.forked_from = Some("parent".into());
            child_config.fork_offset_raw = Some("0".into());
            let child = match store
                .create("child", child_config, Some(parent.clone()), 0)
                .unwrap()
            {
                CreateResult::Created(child) => child,
                _ => panic!("fork create failed"),
            };
            parent_file = parent.file_path.clone();
            child_file = child.file_path.clone();
            parent.shared.write().unwrap().soft_deleted = true;
            write_meta_sync(&parent, true).unwrap();
        }

        let child_meta = meta_path(&child_file);
        std::fs::write(&child_meta, b"{torn-child-sidecar").unwrap();
        File::open(&child_meta).unwrap().sync_all().unwrap();
        fsync_parent_dir(&child_meta).unwrap();
        let parked = child_meta.with_extension("meta.corrupt");

        // Boot 1 discovers and parks the torn sidecar. With an incomplete
        // graph, the potentially linked soft parent must retain its refcount.
        {
            let boot1 = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
            let parent = boot1.streams.get("parent").unwrap().clone();
            assert!(parked.exists());
            assert!(child_file.exists());
            assert_eq!(parent.shared.read().unwrap().ref_count, 1);
            assert_eq!(boot1.recovered_retirement_count(), 0);
        }

        // Boot 2 must classify the parked marker identically. Reclassifying it
        // and its data as disposable orphans would erase the evidence, lower
        // the parent to zero, and make it incorrectly collectible.
        let boot2 = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let parent = boot2.streams.get("parent").unwrap().clone();
        assert!(parked.exists(), "parked corruption evidence was deleted");
        assert!(child_file.exists(), "quarantined child data was deleted");
        assert_eq!(parent.shared.read().unwrap().ref_count, 1);
        assert_eq!(boot2.recovered_retirement_count(), 0);
        let disk_parent: Meta = serde_json::from_slice(
            &std::fs::read(meta_path(&parent_file)).expect("parent sidecar remains"),
        )
        .unwrap();
        assert_eq!(disk_parent.ref_count, 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn quarantined_filename_id_is_reserved_before_the_next_create() {
        let dir = tmp_dir("quarantined-id-reservation");
        drop(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        // Put the parked incarnation above any plausible rolled-back clock seed.
        // Recovery must derive identity from the filename even though its JSON
        // is intentionally unavailable.
        let reserved = MAX_SAFE_INT - 2;
        let filename = format!("parked~{reserved}");
        let data = lane_dir(&dir, lane_of(&filename)).join(filename);
        std::fs::write(&data, b"quarantined-bytes").unwrap();
        std::fs::write(meta_path(&data).with_extension("meta.corrupt"), b"torn").unwrap();

        let recovered = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        assert!(recovered.has_quarantined_streams());
        assert!(recovered.quarantined_stream_ids_complete());
        assert_eq!(recovered.quarantined_stream_ids(), vec![reserved]);
        let created = create(&recovered, "fresh", None, None);
        assert!(
            created.id > reserved,
            "new incarnation reused an id reserved by quarantine"
        );
        assert_ne!(created.file_path, data);
        assert!(data.exists(), "quarantined data was overwritten or removed");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_fork_create_never_publishes_a_child_that_can_ack_appends() {
        let _durability = crate::handlers::test_support::DurabilityGuard::memory();
        let dir = tmp_dir("failed-fork-create-publication");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let parent = create(&store, "parent", None, None);
        let hook = install_create_before_meta_failure_hook(&dir, "child");

        let create_store = Arc::clone(&store);
        let create_parent = Arc::clone(&parent);
        let create_task = tokio::task::spawn_blocking(move || {
            let mut child_config = config(None, None);
            child_config.forked_from = Some("parent".into());
            child_config.fork_offset_raw = Some("0".into());
            create_store.create("child", child_config, Some(create_parent), 0)
        });
        hook.reached();

        let append_store = Arc::clone(&store);
        let mut append_task = tokio::spawn(async move {
            crate::handlers::handle(
                append_store,
                crate::api::Req {
                    method: crate::api::Method::Post,
                    path: "child".into(),
                    query: None,
                    headers: vec![("content-type".into(), "application/octet-stream".into())],
                    body: bytes::Bytes::from_static(b"must-not-be-acked"),
                },
            )
            .await
            .status
        });
        let early = tokio::time::timeout(Duration::from_millis(150), &mut append_task).await;

        // Always unblock and join both paths before asserting so a RED result
        // cannot strand a blocking worker or leave the global hook installed.
        hook.release();
        let create_result = create_task.await.unwrap();
        let append_status = match early {
            Ok(result) => result.unwrap(),
            Err(_) => append_task.await.unwrap(),
        };

        assert!(
            create_result.is_err(),
            "injected child sidecar failure must fail PUT"
        );
        assert_eq!(
            append_status, 404,
            "an uncommitted child became visible to a concurrent append"
        );
        assert!(store.get("child").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unpublished_create_does_not_lock_unrelated_live_lookup() {
        let dir = tmp_dir("create-does-not-lock-lookup");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());

        // Discover a different path in the same DashMap shard without relying
        // on DashMap's private shard-selection implementation. A vacant entry
        // guard locks the target shard, and try_get tells us which candidate
        // maps to it without ever blocking.
        let child = "paused-child";
        let vacant = match store.streams.entry(child.to_owned()) {
            dashmap::mapref::entry::Entry::Vacant(vacant) => vacant,
            dashmap::mapref::entry::Entry::Occupied(_) => unreachable!(),
        };
        let witness = (0..100_000)
            .map(|index| format!("unrelated-live-{index}"))
            .find(|candidate| store.streams.try_get(candidate.as_str()).is_locked())
            .expect("find an unrelated path in the paused create's DashMap shard");
        drop(vacant);
        let witness_state = create(&store, &witness, None, None);

        let hook = install_create_before_meta_failure_hook(&dir, child);
        let create_store = Arc::clone(&store);
        let create_task = tokio::task::spawn_blocking(move || {
            create_store.create(child, config(None, None), None, 0)
        });
        hook.reached();

        let lookup_was_locked = store.streams.try_get(witness.as_str()).is_locked();

        // Always unblock and join the writer before asserting so a RED result
        // cannot strand a blocking worker or leave the hook installed.
        hook.release();
        assert!(create_task.await.unwrap().is_err());
        assert!(Arc::ptr_eq(
            &store.streams.get(witness.as_str()).unwrap(),
            &witness_state
        ));
        assert!(
            !lookup_was_locked,
            "an unpublished create held the DashMap shard write lock across sidecar I/O"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_path_create_waits_for_unpublished_transaction() {
        let dir = tmp_dir("same-path-create-serialization");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let path = "same-path";
        let hook = install_create_before_meta_failure_hook(&dir, path);

        let first_store = Arc::clone(&store);
        let first = tokio::task::spawn_blocking(move || {
            first_store.create(path, config(None, None), None, 0)
        });
        hook.reached();

        let second_store = Arc::clone(&store);
        let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
        let mut second = tokio::task::spawn_blocking(move || {
            let _ = second_started_tx.send(());
            second_store.create(path, config(None, None), None, 0)
        });
        second_started_rx
            .await
            .expect("second create worker started");
        let second_completed_early =
            tokio::time::timeout(Duration::from_millis(150), &mut second).await;

        hook.release();
        assert!(first.await.unwrap().is_err());
        assert!(
            second_completed_early.is_err(),
            "a competing same-path create bypassed the unpublished transaction"
        );
        let created = match second.await.unwrap().unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("the waiter must create after the failed transaction rolls back"),
        };
        assert!(Arc::ptr_eq(&store.streams.get(path).unwrap(), &created));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_publication_cannot_leave_phantom_projections_after_retirement() {
        let dir = tmp_dir("create-publication-projections");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let path = "published-atomically";
        let hook = install_create_after_insert_hook(&dir, path);

        let create_store = Arc::clone(&store);
        let create_task = tokio::task::spawn_blocking(move || {
            create_store.create(path, config(Some(300), None), None, 0)
        });
        hook.reached();

        let inserted = store
            .streams
            .get(path)
            .expect("hook runs after registry insertion")
            .clone();
        assert_eq!(
            store.prepare_delete(&inserted).await,
            PrepareRetirement::Ready
        );
        let candidate = store.candidate_for(&inserted);
        let retire_store = Arc::clone(&store);
        let mut retire_task = tokio::task::spawn_blocking(move || {
            retire_store.finish_retirement_blocking(&candidate, RetirementDurability::Explicit)
        });
        let retired_while_publication_paused =
            tokio::time::timeout(Duration::from_millis(150), &mut retire_task).await;

        // Always unblock and join both operations before asserting so RED
        // cannot strand a blocking worker or leave the scoped hook installed.
        hook.release();
        assert!(matches!(
            create_task.await.unwrap().unwrap(),
            CreateResult::Created(_)
        ));
        let (completed_early, retirement) = match retired_while_publication_paused {
            Ok(result) => (true, result.unwrap()),
            Err(_) => (false, retire_task.await.unwrap()),
        };
        assert_eq!(retirement.unwrap(), RetirementOutcome::Reaped);

        assert!(
            !completed_early,
            "retirement passed the create publication barrier before projections existed"
        );
        assert!(store.streams.get(path).is_none());
        let (_, inventory, _) = store.inventory_page(None, None, 10).unwrap();
        assert!(
            !inventory.iter().any(|entry| entry.path == path),
            "retirement left a phantom inventory row"
        );
        assert_eq!(
            store.expiring_stream_count(),
            0,
            "retirement left a phantom expiration-index entry"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fenced_publication_helpers_do_not_advance_visibility() {
        let dir = tmp_dir("fenced-publication");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let st = create(&store, "stream", None, None);

        st.fenced.store(true, Ordering::Release);
        assert_eq!(
            st.publish_durable_tail_if_live(12),
            Err(StreamAccessError::Expired)
        );
        assert_eq!(
            st.publish_durable_close_if_live(),
            Err(StreamAccessError::Expired)
        );
        assert_eq!(
            st.publish_durable_tail_and_close_if_live(12),
            Err(StreamAccessError::Expired)
        );
        assert_eq!(
            st.with_live_shared_mut(|shared| shared.last_access = UNIX_EPOCH),
            Err(StreamAccessError::Expired)
        );
        let shared = st.shared.read().unwrap();
        assert_eq!(shared.durable_tail, 0);
        assert!(!shared.closed_durable);
        assert_ne!(shared.last_access, UNIX_EPOCH);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn body_close_publication_is_one_atomic_monotonic_transition() {
        let dir = tmp_dir("body-close-publication");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let st = create(&store, "stream", None, None);

        let (published, advanced) = st.publish_durable_tail_and_close_if_live(12).unwrap();
        assert!(advanced);
        assert_eq!(
            published,
            Tail {
                bytes: 12,
                closed: true
            }
        );
        let (published, advanced) = st.publish_durable_tail_and_close_if_live(8).unwrap();
        assert!(!advanced);
        assert_eq!(published.bytes, 12, "durable visibility never regresses");
        assert!(published.closed);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lookup_without_ttl_touch_stays_on_the_shared_read_path() {
        let dir = tmp_dir("lookup-read-lock");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let st = create(&store, "stream", None, None);
        let held_read = st.shared.read().unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);

        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let live = matches!(
                    store.lookup_at("stream", SystemTime::now(), false),
                    StreamLookup::Live(_)
                );
                tx.send(live).unwrap();
            });
            let result = rx.recv_timeout(Duration::from_secs(1));
            // Always unblock an accidentally exclusive implementation before
            // joining, so the regression fails deterministically rather than
            // hanging the test process.
            drop(held_read);
            assert!(result.unwrap());
            handle.join().unwrap();
        });

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_rebuilds_indexes_without_unbounded_tombstone_cleanup() {
        let dir = tmp_dir("recovery");
        let expiring_path;
        let abandoned_path;
        {
            let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
            let expiring = create(&store, "expiring", Some(60), None);
            let _permanent = create(&store, "permanent", None, None);
            let abandoned = create(&store, "abandoned", Some(60), None);
            abandoned.shared.write().unwrap().soft_deleted = true;
            write_meta_sync(&abandoned, true).unwrap();
            expiring_path = expiring.file_path.clone();
            abandoned_path = abandoned.file_path.clone();
        }

        let recovered = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        assert_eq!(recovered.expiring_stream_count(), 1);
        assert!(recovered.streams.contains_key("expiring"));
        assert!(expiring_path.exists());
        assert!(recovered.streams.contains_key("abandoned"));
        assert!(abandoned_path.exists());
        assert!(meta_path(&abandoned_path).exists());
        let abandoned = recovered.streams.get("abandoned").unwrap().clone();
        assert!(abandoned.is_fenced());
        let mut cursor = ExpiryScanCursor::default();
        let page = recovered.scan_recovered_retirements(&mut cursor, 1);
        assert_eq!(page.checked, 1);
        assert!(page.completed_pass);
        assert_eq!(recovered.recovered_retirement_count(), 1);
        assert_eq!(page.due[0].stream_id(), abandoned.id);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fork_reference_reservation_rejects_a_fenced_parent() {
        let dir = tmp_dir("fork-fence");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let parent = create(&store, "parent", None, None);
        parent.fenced.store(true, Ordering::Release);

        assert!(matches!(
            store
                .create("child", config(None, None), Some(parent.clone()), 0)
                .unwrap(),
            CreateResult::SourceUnavailable
        ));
        assert_eq!(parent.shared.read().unwrap().ref_count, 0);
        assert!(!store.streams.contains_key("child"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fork_reservation_does_not_persist_an_inflight_append_snapshot() {
        let _durability = crate::handlers::test_support::DurabilityGuard::wal();
        let dir = tmp_dir("fork-parent-inflight-meta");
        let crash_dir = tmp_dir("fork-parent-inflight-meta-crash");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let wal = crate::wal::walset::WalSet::open(&dir, Some(1), 1).unwrap();
        store.wal.set(Arc::clone(&wal)).unwrap_or_else(|_| panic!());
        wal.spawn_committers();

        let mut parent_config = config(Some(3_600), None);
        parent_config.create_closed = false;
        let parent = match store.create("parent", parent_config, None, 0).unwrap() {
            CreateResult::Created(parent) => parent,
            _ => panic!("parent create failed"),
        };
        let durable_last_access = UNIX_EPOCH
            + Duration::from_secs(
                unix_secs(SystemTime::now())
                    .checked_sub(10)
                    .expect("test clock is after the Unix epoch"),
            );
        parent.shared.write().unwrap().last_access = durable_last_access;
        write_meta_sync(&parent, true).unwrap();

        // Freeze the append at the WAL's first staging instruction. At this
        // point write_wire + the close/dedupe mutations have happened under the
        // appender, but no LSN has even been reserved and nothing can be durable.
        let reached = Arc::new(Notify::new());
        let release = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        let shard = wal.shard_for(parent.id);
        let parent_id = parent.id;
        shard.set_on_stage_hook(Box::new({
            let reached = Arc::clone(&reached);
            let release = Arc::clone(&release);
            move |stream_id| {
                assert_eq!(stream_id, parent_id);
                reached.notify_one();
                let (lock, wake) = &*release;
                let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(|error| error.into_inner());
                }
            }
        }));
        let staged = reached.notified();
        let append = tokio::spawn(crate::handlers::handle(
            Arc::clone(&store),
            crate::api::Req {
                method: crate::api::Method::Post,
                path: "parent".into(),
                query: None,
                headers: vec![
                    ("content-type".into(), "application/octet-stream".into()),
                    ("stream-closed".into(), "true".into()),
                    ("producer-id".into(), "producer-a".into()),
                    ("producer-epoch".into(), "1".into()),
                    ("producer-seq".into(), "0".into()),
                    ("stream-seq".into(), "seq-a".into()),
                ],
                body: bytes::Bytes::from_static(b"unacknowledged"),
            },
        ));
        staged.await;
        assert_eq!(shard.durable_lsn(), 0, "paused append became durable");

        let create_store = Arc::clone(&store);
        let create_parent = Arc::clone(&parent);
        let child = tokio::task::spawn_blocking(move || {
            let mut child_config = config(None, None);
            child_config.forked_from = Some("parent".into());
            child_config.fork_offset_raw = Some("0".into());
            create_store.create("child", child_config, Some(create_parent), 0)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(child, CreateResult::Created(_)));

        // Copy the exact pre-ack parent data+sidecar into a separate boot image.
        // Store recovery runs before WAL replay in production, so this proves
        // which request state the fork reservation made crash-durable.
        drop(Store::new_with_tier(crash_dir.clone(), TierConfig::default()).unwrap());
        let relative = parent.file_path.strip_prefix(&dir).unwrap();
        let crash_file = crash_dir.join(relative);
        std::fs::create_dir_all(crash_file.parent().unwrap()).unwrap();
        std::fs::copy(&parent.file_path, &crash_file).unwrap();
        std::fs::copy(meta_path(&parent.file_path), meta_path(&crash_file)).unwrap();
        let recovered = Store::new_with_tier(crash_dir.clone(), TierConfig::default()).unwrap();
        let recovered_parent = recovered.streams.get("parent").unwrap().clone();
        let recovered_state = {
            let shared = recovered_parent.shared.read().unwrap();
            (
                shared.closed,
                shared.producers.contains_key("producer-a"),
                shared.last_seq_header.clone(),
                shared.last_access,
            )
        };

        // Always release and join the real request before asserting the crash
        // image, so a RED result cannot strand a WAL committer or test worker.
        {
            let (lock, wake) = &*release;
            *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
            wake.notify_all();
        }
        let response = append.await.unwrap();
        shard.set_on_stage_hook(Box::new(|_| {}));
        wal.stop_committers();

        assert!((200..300).contains(&response.status));
        assert_eq!(
            recovered_state,
            (false, false, None, durable_last_access),
            "fork refcount persistence leaked unacknowledged append metadata"
        );

        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(crash_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_refcount_release_does_not_persist_an_inflight_append_snapshot() {
        let _durability = crate::handlers::test_support::DurabilityGuard::wal();
        let dir = tmp_dir("parent-release-inflight-meta");
        let crash_dir = tmp_dir("parent-release-inflight-meta-crash");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let wal = crate::wal::walset::WalSet::open(&dir, Some(1), 1).unwrap();
        store.wal.set(Arc::clone(&wal)).unwrap_or_else(|_| panic!());
        wal.spawn_committers();

        let mut parent_config = config(Some(3_600), None);
        parent_config.create_closed = false;
        let parent = match store.create("parent", parent_config, None, 0).unwrap() {
            CreateResult::Created(parent) => parent,
            _ => panic!("parent create failed"),
        };
        let durable_last_access = UNIX_EPOCH
            + Duration::from_secs(
                unix_secs(SystemTime::now())
                    .checked_sub(10)
                    .expect("test clock is after the Unix epoch"),
            );
        parent.shared.write().unwrap().last_access = durable_last_access;
        write_meta_sync(&parent, true).unwrap();

        let mut child_config = config(None, None);
        child_config.forked_from = Some("parent".into());
        child_config.fork_offset_raw = Some("0".into());
        let child = match store
            .create("child", child_config, Some(parent.clone()), 0)
            .unwrap()
        {
            CreateResult::Created(child) => child,
            _ => panic!("child create failed"),
        };
        assert_eq!(parent.shared.read().unwrap().ref_count, 1);

        // Freeze a parent append after write_wire and its close/dedupe/TTL
        // mutations, but before it reserves an LSN or reaches durability.
        let reached = Arc::new(Notify::new());
        let release = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        let shard = wal.shard_for(parent.id);
        let parent_id = parent.id;
        shard.set_on_stage_hook(Box::new({
            let reached = Arc::clone(&reached);
            let release = Arc::clone(&release);
            move |stream_id| {
                assert_eq!(stream_id, parent_id);
                reached.notify_one();
                let (lock, wake) = &*release;
                let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(|error| error.into_inner());
                }
            }
        }));
        let staged = reached.notified();
        let append = tokio::spawn(crate::handlers::handle(
            Arc::clone(&store),
            crate::api::Req {
                method: crate::api::Method::Post,
                path: "parent".into(),
                query: None,
                headers: vec![
                    ("content-type".into(), "application/octet-stream".into()),
                    ("stream-closed".into(), "true".into()),
                    ("producer-id".into(), "producer-a".into()),
                    ("producer-epoch".into(), "1".into()),
                    ("producer-seq".into(), "0".into()),
                    ("stream-seq".into(), "seq-a".into()),
                ],
                body: bytes::Bytes::from_static(b"unacknowledged"),
            },
        ));
        staged.await;
        assert_eq!(shard.durable_lsn(), 0, "paused append became durable");

        // Hard-retiring the only child releases the live parent's final fork
        // reference. That lifecycle write may persist ref_count=0, but must not
        // snapshot any of the parent's unacknowledged append state.
        assert_eq!(store.prepare_delete(&child).await, PrepareRetirement::Ready);
        let retired = store
            .finish_retirement(&store.candidate_for(&child), RetirementDurability::Explicit)
            .await
            .unwrap();
        assert_eq!(retired.outcome, RetirementOutcome::Reaped);
        assert!(retired.cascade.is_none());
        assert_eq!(parent.shared.read().unwrap().ref_count, 0);

        // Copy the exact pre-ack parent image and recover it independently.
        drop(Store::new_with_tier(crash_dir.clone(), TierConfig::default()).unwrap());
        let relative = parent.file_path.strip_prefix(&dir).unwrap();
        let crash_file = crash_dir.join(relative);
        std::fs::create_dir_all(crash_file.parent().unwrap()).unwrap();
        std::fs::copy(&parent.file_path, &crash_file).unwrap();
        std::fs::copy(meta_path(&parent.file_path), meta_path(&crash_file)).unwrap();
        let recovered = Store::new_with_tier(crash_dir.clone(), TierConfig::default()).unwrap();
        let recovered_parent = recovered.streams.get("parent").unwrap().clone();
        let recovered_state = {
            let shared = recovered_parent.shared.read().unwrap();
            (
                shared.ref_count,
                shared.closed,
                shared.producers.contains_key("producer-a"),
                shared.last_seq_header.clone(),
                shared.last_access,
            )
        };

        // Always release and join the real append before asserting, so a RED
        // result cannot strand a WAL committer or test worker.
        {
            let (lock, wake) = &*release;
            *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
            wake.notify_all();
        }
        let response = append.await.unwrap();
        shard.set_on_stage_hook(Box::new(|_| {}));
        wal.stop_committers();

        assert!((200..300).contains(&response.status));
        assert_eq!(
            recovered_state,
            (0, false, false, None, durable_last_access),
            "parent refcount release leaked unacknowledged append metadata"
        );

        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(crash_dir);
    }

    #[test]
    fn parent_refcount_release_rolls_back_when_the_narrow_merge_fails() {
        let dir = tmp_dir("parent-release-refcount-rollback");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let parent = create(&store, "parent", None, None);
        let child = match store
            .create("child", config(None, None), Some(parent.clone()), 0)
            .unwrap()
        {
            CreateResult::Created(child) => child,
            _ => panic!("child create failed"),
        };
        assert_eq!(parent.shared.read().unwrap().ref_count, 1);

        // A missing durable parent sidecar makes the narrow merge fail after
        // the in-memory decrement. The lifecycle reservation must become
        // retryable again and the reference must remain authoritative.
        std::fs::remove_file(meta_path(&parent.file_path)).unwrap();
        let error = match store.release_parent_once(&child, RetirementDurability::Explicit) {
            Ok(_) => panic!("missing parent sidecar must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(parent.shared.read().unwrap().ref_count, 1);
        assert!(!child.parent_released.load(Ordering::Acquire));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn fork_reference_reservation_does_not_contend_on_parent_appender() {
        let dir = tmp_dir("fork-appender-contention");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let parent = create(&store, "parent", None, None);
        let _ordinary_append = parent.appender.lock().await;
        let mut child_config = config(None, None);
        child_config.forked_from = Some("parent".into());
        child_config.fork_offset_raw = Some("0".into());

        let child = match store
            .create("child", child_config, Some(parent.clone()), 0)
            .expect("ordinary source append contention must not reject a fork reservation")
        {
            CreateResult::Created(child) => child,
            _ => panic!("valid fork reservation was rejected"),
        };
        assert_eq!(
            child.parent.as_ref().map(|source| source.id),
            Some(parent.id)
        );
        assert_eq!(parent.shared.read().unwrap().ref_count, 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fork_reservation_rollback_precedes_retirement_soft_delete_decision() {
        let dir = tmp_dir("fork-rollback-retirement");
        let store = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        let parent = create(&store, "parent", None, None);

        // Model create after it owns the source metadata transaction and has
        // reserved one ref, immediately before a child-sidecar failure.
        let source_meta = parent
            .meta_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        parent.shared.write().unwrap().ref_count = 1;
        parent.fenced.store(true, Ordering::Release);
        let candidate = store.candidate_for(&parent);
        let start = Arc::new(std::sync::Barrier::new(2));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker_store = Arc::clone(&store);
        let worker_start = Arc::clone(&start);
        let worker = std::thread::spawn(move || {
            worker_start.wait();
            let outcome = worker_store
                .finish_retirement_blocking_once(&candidate, RetirementDurability::Explicit)
                .unwrap()
                .outcome;
            done_tx.send(outcome).unwrap();
        });
        start.wait();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        // Child metadata failed: rollback wins while retirement is blocked on
        // the same barrier. It must observe the final zero, not leak a
        // same-process zero-ref SoftDeleted tombstone.
        parent.shared.write().unwrap().ref_count = 0;
        drop(source_meta);
        assert_eq!(
            done_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            RetirementOutcome::Reaped
        );
        worker.join().unwrap();

        let _ = std::fs::remove_dir_all(dir);
    }
}
