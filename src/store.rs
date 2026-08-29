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
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::{watch, Mutex as AsyncMutex};

pub const MAX_SAFE_INT: u64 = (1u64 << 53) - 1;

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
    #[allow(dead_code)]
    pub(crate) fenced: AtomicBool,
    #[allow(dead_code)]
    pub(crate) inflight_appends: AtomicUsize,
    #[allow(dead_code)]
    pub(crate) inflight_appends_zero: tokio::sync::Notify,
    /// Never persisted: deduplication, attempt count, and failure cooldown are
    /// rebuilt on create and recovery by the retirement foundation.
    pub(crate) retirement_state: StdMutex<crate::retirement::RetirementState>,
    #[allow(dead_code)]
    pub(crate) deletion_tx: watch::Sender<bool>,
    pub shared: RwLock<Shared>,
    pub tail_tx: watch::Sender<Tail>,
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

#[allow(dead_code)]
pub(crate) struct InflightAppendGuard {
    stream: Arc<StreamState>,
}

#[allow(dead_code)]
impl InflightAppendGuard {
    pub(crate) fn begin(
        stream: &Arc<StreamState>,
        _appender: &tokio::sync::MutexGuard<'_, Appender>,
    ) -> Option<Self> {
        if stream.fenced.load(Ordering::Acquire) {
            return None;
        }

        stream.inflight_appends.fetch_add(1, Ordering::AcqRel);
        Some(Self {
            stream: stream.clone(),
        })
    }
}

impl Drop for InflightAppendGuard {
    fn drop(&mut self) {
        let previous = self.stream.inflight_appends.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "in-flight append count underflowed");
        if previous == 1 {
            self.stream.inflight_appends_zero.notify_waiters();
        }
    }
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

#[allow(dead_code)]
impl StreamState {
    /// Fences this stream while `_appender` is the guard from this stream's
    /// appender mutex; the parameter makes that caller-side invariant explicit.
    pub(crate) fn fence_while_holding_appender(
        &self,
        _appender: &tokio::sync::MutexGuard<'_, Appender>,
    ) {
        self.fenced.store(true, Ordering::Release);
    }

    /// Waits for in-flight append guards to drain after the stream was fenced
    /// under its appender lock.
    pub(crate) async fn wait_for_inflight_appends_zero(&self) {
        loop {
            let notified = self.inflight_appends_zero.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if self.inflight_appends.load(Ordering::Acquire) == 0 {
                return;
            }

            notified.await;
        }
    }

    pub(crate) fn subscribe_deletion(&self) -> watch::Receiver<bool> {
        self.deletion_tx.subscribe()
    }

    pub(crate) fn signal_deletion(&self) {
        self.deletion_tx.send_replace(true);
    }

    /// Wake every reader after retirement has fenced and drained this stream.
    /// Both explicit and expiry retirement use this single level-triggered path.
    pub(crate) fn wake_deletion(&self) {
        self.signal_deletion();
        #[cfg(target_os = "linux")]
        crate::sse_reactor::close_stream_for_deletion(self);
    }

    /// Retirement state is process-local; a prior holder panicking must not
    /// permanently prevent a later bounded retirement attempt.
    pub(crate) fn retirement_state(&self) -> StdMutexGuard<'_, crate::retirement::RetirementState> {
        self.retirement_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl StreamState {
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

    pub fn touch(&self) {
        let mut s = self.shared.write().unwrap();
        s.last_access = SystemTime::now();
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(SystemTime::now())
    }

    /// Returns the earliest finite expiry deadline, or `None` when none exists.
    ///
    /// This acquires `shared.read()` internally; callers must not already hold
    /// the shared lock.
    pub fn expiry_deadline(&self) -> Option<SystemTime> {
        let ttl_deadline = self.config.ttl_seconds.and_then(|ttl_seconds| {
            self.shared
                .read()
                .unwrap()
                .last_access
                .checked_add(Duration::from_secs(ttl_seconds))
        });

        match (self.config.expires_at, ttl_deadline) {
            (Some(absolute), Some(ttl)) => Some(absolute.min(ttl)),
            (Some(absolute), None) => Some(absolute),
            (None, Some(ttl)) => Some(ttl),
            (None, None) => None,
        }
    }

    /// Applies the protocol's strict expiration boundary: `now > deadline`.
    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expiry_deadline()
            .is_some_and(|deadline| now > deadline)
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
    /// Process-lifetime bounded physical cleanup pool. It is installed only
    /// after recovery completes, before the server becomes reachable.
    retirement_executor: std::sync::OnceLock<Arc<crate::retirement::RetirementExecutor>>,
    /// Serializes initialization so a racing second initializer cannot spawn a
    /// discarded worker pool before losing `OnceLock::set`.
    retirement_init: StdMutex<()>,
    /// Streams with a pending non-durable sidecar flush (memory-mode appends,
    /// TTL read touches), drained in batch by the periodic meta sweeper
    /// (`sweep_meta_once`). The `meta_dirty` CAS in `mark_meta_dirty` keeps
    /// each stream in here at most once per sweep cycle (#4691).
    pub meta_sweep: StdMutex<Vec<Arc<StreamState>>>,
    pub subscriptions: Arc<crate::subscriptions::SubscriptionManager>,
    inventory: RwLock<InventoryProjection>,
}

/// A read-only stream projection used by the bounded administrative inventory.
#[derive(Clone, Debug)]
pub struct InventoryEntry {
    pub path: String,
    pub closed: bool,
    pub deleted: bool,
    pub durable_bytes: u64,
    stream_id: u64,
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
    Conflict,
}

/// Local cleanup durability requested by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalCleanupMode {
    /// An acknowledged DELETE: make every successful local unlink durable.
    ExplicitDelete,
    /// Lazy expiry: unlink synchronously, but permit crash resurrection before
    /// the directory entry is synced.
    Expiry,
}

/// Files reclaimed by one synchronous local cleanup attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LocalCleanupOutcome {
    pub(crate) reclaimed_local_bytes: u64,
}

/// Outcome of one exact explicit-retirement attempt. The caller that receives
/// `Owner` alone performed the Store linearization; duplicates share its ticket.
#[allow(dead_code)] // TODO(retirement-005c): handlers consume this result.
pub(crate) enum ExplicitRetirementResult {
    Owner(crate::retirement::RetirementTicket),
    Existing(crate::retirement::RetirementTicket),
    Missing,
    Gone,
    Stale,
    Rejected(crate::retirement::RetirementAdmission),
    Unavailable,
    Cancelled(crate::retirement::RetirementTicket),
}

impl Store {
    fn publish_inventory(&self, st: &StreamState) {
        // Keep the registry shard locked through projection publication. A
        // replacement cannot install between this identity check and the write.
        let Some(current) = self.streams.get(&st.path) else {
            return;
        };
        if current.id != st.id {
            return;
        }
        let s = st.shared.read().unwrap();
        let entry = InventoryEntry {
            path: st.path.clone(),
            closed: s.closed_durable,
            deleted: s.soft_deleted,
            durable_bytes: s.durable_tail,
            stream_id: st.id,
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
                    path: stream.path.clone(),
                    closed: shared.closed_durable,
                    deleted: shared.soft_deleted,
                    durable_bytes: shared.durable_tail,
                    stream_id: stream.id,
                },
            );
        }
        let mut inventory = self.inventory.write().unwrap();
        inventory.entries = entries;
        inventory.generation = inventory.generation.wrapping_add(1);
    }
    fn remove_inventory(&self, path: &str, expected_id: u64) {
        let mut inventory = self.inventory.write().unwrap();
        if inventory
            .entries
            .get(path)
            .is_some_and(|entry| entry.stream_id == expected_id)
        {
            inventory.entries.remove(path);
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
        let store = Store {
            streams: DashMap::new(),
            data_dir,
            next_id: AtomicU64::new(seed & MAX_SAFE_INT),
            tier_config,
            blobstore,
            wal: std::sync::OnceLock::new(),
            retirement_executor: std::sync::OnceLock::new(),
            retirement_init: StdMutex::new(()),
            meta_sweep: StdMutex::new(Vec::new()),
            subscriptions: Arc::new(crate::subscriptions::SubscriptionManager::new()?),
            inventory: RwLock::new(InventoryProjection {
                generation: 0,
                entries: BTreeMap::new(),
            }),
        };
        store.recover(&streams_dir)?;
        Ok(store)
    }

    /// Install the one process-lifetime retirement executor after recovery.
    ///
    /// Requiring `Arc<Self>` makes the callback's weak Store capture explicit.
    /// The initialization mutex covers construction as well as `OnceLock::set`,
    /// so a second caller fails before it can spawn another fixed worker pool.
    pub(crate) fn init_retirement_executor(
        self: &Arc<Self>,
    ) -> std::io::Result<&Arc<crate::retirement::RetirementExecutor>> {
        let _init = self
            .retirement_init
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.retirement_executor.get().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "retirement executor already initialized",
            ));
        }

        let store = Arc::downgrade(self);
        let cleanup: crate::retirement::CleanupCallback = Arc::new(move |stream, mode| {
            let store = store.upgrade().ok_or_else(|| {
                std::io::Error::other("retirement cleanup ran after Store was dropped")
            })?;
            store.finalize_retirement_cleanup(stream, mode)
        });
        let executor = Arc::new(
            crate::retirement::RetirementExecutor::new(
                cleanup,
                crate::retirement::RetirementConfig::default(),
            )
            .map_err(std::io::Error::other)?,
        );
        self.retirement_executor
            .set(executor)
            .map_err(|_| std::io::Error::other("retirement executor initialization raced"))?;
        Ok(self
            .retirement_executor
            .get()
            .expect("retirement executor was just initialized"))
    }

    /// Narrow access point for the later Store retirement mutations.
    pub(crate) fn retirement_executor(
        &self,
    ) -> Option<&Arc<crate::retirement::RetirementExecutor>> {
        self.retirement_executor.get()
    }

    /// Retire one exact registered stream incarnation. This only linearizes
    /// Store state and schedules the bounded physical phase; 005c maps the
    /// returned ticket to the explicit DELETE response.
    #[allow(dead_code)] // TODO(retirement-005c): explicit DELETE calls this.
    pub(crate) async fn retire_explicit(
        self: &Arc<Self>,
        stream: Arc<StreamState>,
    ) -> ExplicitRetirementResult {
        match self.streams.get(&stream.path) {
            None => return ExplicitRetirementResult::Missing,
            Some(current) if current.id != stream.id || !Arc::ptr_eq(current.value(), &stream) => {
                return ExplicitRetirementResult::Stale;
            }
            Some(_) => {}
        }
        if stream.shared.read().unwrap().soft_deleted {
            return ExplicitRetirementResult::Gone;
        }
        let Some(executor) = self.retirement_executor() else {
            return ExplicitRetirementResult::Unavailable;
        };
        let executor = Arc::clone(executor);
        let ticket = match executor.admit(
            stream.clone(),
            crate::retirement::RetirementPriority::Interactive,
            LocalCleanupMode::ExplicitDelete,
        ) {
            crate::retirement::RetirementAdmissionResult::Admitted(ticket) => ticket,
            crate::retirement::RetirementAdmissionResult::Existing(ticket) => {
                return ExplicitRetirementResult::Existing(ticket);
            }
            crate::retirement::RetirementAdmissionResult::Rejected(reason) => {
                return ExplicitRetirementResult::Rejected(reason);
            }
        };

        {
            let appender = stream.appender.lock().await;
            if !self.is_exact_live(&stream) || stream.fenced.load(Ordering::Acquire) {
                drop(appender);
                return self.cancel_explicit_retirement(&executor, &stream, ticket);
            }
            stream.fence_while_holding_appender(&appender);
        }
        stream.wait_for_inflight_appends_zero().await;

        if !self.is_exact_live(&stream) {
            return self.cancel_explicit_retirement(&executor, &stream, ticket);
        }
        stream.wake_deletion();
        self.subscriptions
            .clone()
            .on_stream_deleted(Arc::clone(self), &stream.path)
            .await;
        if !self.is_exact_live(&stream) {
            return self.cancel_explicit_retirement(&executor, &stream, ticket);
        }

        let soft_deleted = {
            let mut shared = stream.shared.write().unwrap();
            if shared.soft_deleted {
                return self.cancel_explicit_retirement(&executor, &stream, ticket);
            }
            if shared.ref_count > 0 {
                shared.soft_deleted = true;
                true
            } else {
                false
            }
        };
        if !soft_deleted {
            let removed = self.streams.remove_if(&stream.path, |_, current| {
                current.id == stream.id && Arc::ptr_eq(current, &stream)
            });
            if removed.is_none() {
                return self.cancel_explicit_retirement(&executor, &stream, ticket);
            }
            self.remove_inventory(&stream.path, stream.id);
        }

        if executor.release_logical(&stream, &ticket) {
            ExplicitRetirementResult::Owner(ticket)
        } else {
            if !soft_deleted {
                self.restore_exact_registration(&stream);
            }
            ExplicitRetirementResult::Cancelled(ticket)
        }
    }

    #[allow(dead_code)]
    fn cancel_explicit_retirement(
        &self,
        executor: &crate::retirement::RetirementExecutor,
        stream: &Arc<StreamState>,
        ticket: crate::retirement::RetirementTicket,
    ) -> ExplicitRetirementResult {
        let _ = executor.cancel_prelogical(stream, &ticket);
        ExplicitRetirementResult::Cancelled(ticket)
    }

    fn is_exact_registered(&self, stream: &Arc<StreamState>) -> bool {
        self.streams
            .get(&stream.path)
            .is_some_and(|current| current.id == stream.id && Arc::ptr_eq(current.value(), stream))
    }

    #[allow(dead_code)]
    fn is_exact_live(&self, stream: &Arc<StreamState>) -> bool {
        self.is_exact_registered(stream) && !stream.shared.read().unwrap().soft_deleted
    }

    #[allow(dead_code)]
    fn restore_exact_registration(&self, stream: &Arc<StreamState>) {
        use dashmap::mapref::entry::Entry;

        let restored = match self.streams.entry(stream.path.clone()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(stream.clone());
                true
            }
        };
        if restored {
            self.publish_inventory(stream);
        }
    }

    /// Physical finalizer for an already-linearized retirement. It deliberately
    /// performs no registry mutation: the logical path owns that transition.
    fn finalize_retirement_cleanup(
        &self,
        stream: &Arc<StreamState>,
        mode: LocalCleanupMode,
    ) -> std::io::Result<LocalCleanupOutcome> {
        if !stream.fenced.load(Ordering::Acquire) {
            return Err(std::io::Error::other(
                "retirement cleanup requires a fenced stream",
            ));
        }
        if stream.shared.read().unwrap().soft_deleted {
            if !self.is_exact_registered(stream) {
                return Err(std::io::Error::other(
                    "soft retirement lost its exact registry tombstone",
                ));
            }
            write_meta_sync(stream, true)?;
            self.publish_inventory(stream);
            return Ok(LocalCleanupOutcome::default());
        }
        if self.is_exact_registered(stream) {
            return Err(std::io::Error::other(
                "hard retirement must leave the registry before cleanup",
            ));
        }
        self.gc_remote_segments(stream);
        let outcome = self.cleanup_local_stream(stream, mode)?;
        self.release_parent(stream);
        Ok(outcome)
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
        let mut max_id = 0u64;
        let paths: Vec<String> = metas.keys().cloned().collect();
        // `visiting` tracks the active recursion stack to break cyclic
        // forked_from chains in corrupt sidecars (would otherwise overflow the
        // stack on boot). It self-empties between top-level calls.
        let mut visiting = HashSet::new();
        for path in paths {
            self.recover_one(&path, &metas, &mut visiting);
        }
        for (m, _) in metas.values() {
            max_id = max_id.max(m.id);
        }
        // Keep ids unique across restarts (they feed ETags).
        let cur = self.next_id.load(Ordering::Relaxed);
        self.next_id.store(cur.max(max_id + 1), Ordering::Relaxed);
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
        let (deletion_tx, _) = watch::channel(false);
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
            fenced: AtomicBool::new(false),
            inflight_appends: AtomicUsize::new(0),
            inflight_appends_zero: tokio::sync::Notify::new(),
            retirement_state: StdMutex::new(crate::retirement::RetirementState::default()),
            deletion_tx,
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
            write_meta_sync(&state, true).unwrap_or_else(|e| {
                panic!(
                    "recovery: cannot durably clear the compaction intent for {} ({e}); \
                     booting without it risks a mis-derived file_base after another crash",
                    state.file_path.display()
                )
            });
        }
        self.streams.insert(path.to_string(), state.clone());
        Some(state)
    }

    /// Look up a stream. Expired streams are removed (or soft-deleted when forks
    /// still reference them). Soft-deleted entries ARE returned — callers decide
    /// between 410 (direct ops) and 409 (PUT re-create / fork source).
    pub fn get(&self, path: &str) -> Option<Arc<StreamState>> {
        let st = self.streams.get(path)?.clone();
        if st.shared.read().unwrap().soft_deleted {
            return Some(st);
        }
        if st.is_expired() {
            // Expiry retains the projection until synchronous local unlink
            // succeeds; unlike an acknowledged DELETE it does not sync the
            // parent directory, so a crash may resurrect the old incarnation.
            let _ = self.delete_or_soft_delete_expiry(&st);
            return None;
        }
        Some(st)
    }

    /// Remove an expired stream synchronously without syncing the parent
    /// directory. A crash can resurrect its unlinked files, which is acceptable
    /// for lazy expiry; I/O errors are still returned to the caller.
    pub(crate) fn delete_or_soft_delete_expiry(
        &self,
        st: &Arc<StreamState>,
    ) -> std::io::Result<LocalCleanupOutcome> {
        self.delete_impl(st, LocalCleanupMode::Expiry)
    }

    /// Hard-delete when nothing references the stream; soft-delete otherwise,
    /// with the DELETE-ack durability contract:
    /// the file + sidecar unlinks (and their parent-directory entry) — or the
    /// soft-delete meta flag — are durable on disk before this returns, so a
    /// post-ack crash can never resurrect the stream. Synchronous file I/O +
    /// fsync: call from a blocking context.
    pub fn delete_or_soft_delete_durable(
        &self,
        st: &Arc<StreamState>,
    ) -> std::io::Result<LocalCleanupOutcome> {
        self.delete_impl(st, LocalCleanupMode::ExplicitDelete)
    }

    fn delete_impl(
        &self,
        st: &Arc<StreamState>,
        mode: LocalCleanupMode,
    ) -> std::io::Result<LocalCleanupOutcome> {
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
            if let Err(error) = write_meta_sync(st, true) {
                st.shared.write().unwrap().soft_deleted = false;
                return Err(error);
            }
            self.publish_inventory(st);
            Ok(LocalCleanupOutcome::default())
        } else {
            // Reclaim this stream's offloaded segments (remote objects + any
            // staged local chunk files) — safe only here, on a true hard delete
            // with no remaining fork references.
            self.gc_remote_segments(st);
            let outcome = self.cleanup_local_stream(st, mode)?;
            let removed = self.streams.remove_if(&st.path, |_, current| {
                current.id == st.id && Arc::ptr_eq(current, st)
            });
            if removed.is_some() {
                self.remove_inventory(&st.path, st.id);
                self.release_parent(st);
            }
            Ok(outcome)
        }
    }

    /// Synchronously reclaim local files for this exact stream incarnation.
    /// NotFound is an idempotent retry; all other metadata, unlink, and sync
    /// errors are surfaced without changing registry or inventory state.
    pub(crate) fn cleanup_local_stream(
        &self,
        st: &StreamState,
        mode: LocalCleanupMode,
    ) -> std::io::Result<LocalCleanupOutcome> {
        #[cfg(test)]
        if DELETE_FAULT.load(Ordering::Relaxed) == 2 {
            return Err(std::io::Error::other("injected local cleanup failure"));
        }

        let mut paths = HashSet::from([st.file_path.clone(), meta_path(&st.file_path)]);
        {
            let manifest = st.tier.manifest.lock().unwrap();
            paths.extend(
                manifest
                    .segments
                    .iter()
                    .filter_map(|segment| match &segment.placement {
                        crate::tier::Placement::Local(path) => Some(path.clone()),
                        crate::tier::Placement::Remote(_) => None,
                    }),
            );
        }
        let file_prefix = format!(
            "{}.seg.",
            st.file_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("stream")
        );
        match std::fs::read_dir(self.segments_dir()) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    if entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(&file_prefix))
                    {
                        paths.insert(entry.path());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let _meta_lock = st
            .meta_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut outcome = LocalCleanupOutcome::default();
        for path in &paths {
            let bytes = match std::fs::metadata(path) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            match std::fs::remove_file(path) {
                Ok(()) => outcome.reclaimed_local_bytes += bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        if mode == LocalCleanupMode::ExplicitDelete {
            #[cfg(test)]
            if DELETE_FAULT.load(Ordering::Relaxed) == 3 {
                return Err(std::io::Error::other(
                    "injected parent-directory sync failure",
                ));
            }
            let mut synced_dirs = HashSet::new();
            for path in &paths {
                if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
                    if synced_dirs.insert(parent.to_path_buf()) {
                        match File::open(parent) {
                            Ok(directory) => directory.sync_all()?,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
            }
        }
        Ok(outcome)
    }

    /// Decrement the parent's fork refcount; cascade-collect soft-deleted parents
    /// whose last fork just went away.
    pub fn release_parent(&self, st: &Arc<StreamState>) {
        let mut cur = st.parent.clone();
        while let Some(parent) = cur {
            let gone = {
                let mut s = parent.shared.write().unwrap();
                s.ref_count = s.ref_count.saturating_sub(1);
                s.soft_deleted && s.ref_count == 0
            };
            if !gone {
                // Persist the decremented refcount.
                let p2 = parent.clone();
                tokio::task::spawn_blocking(move || {
                    let _ = write_meta_sync(&p2, true);
                });
                break;
            }
            self.streams
                .remove_if(&parent.path, |_, v| Arc::ptr_eq(v, &parent));
            self.gc_remote_segments(&parent);
            let fp = parent.file_path.clone();
            tokio::task::spawn_blocking(move || {
                let _ = std::fs::remove_file(meta_path(&fp));
                let _ = std::fs::remove_file(fp);
            });
            cur = parent.parent.clone();
        }
    }

    pub fn create(
        &self,
        path: &str,
        config: StreamConfig,
        parent: Option<Arc<StreamState>>,
        base_offset: u64,
    ) -> std::io::Result<CreateResult> {
        use dashmap::mapref::entry::Entry;
        // Fast path: existing stream → config comparison.
        if let Some(existing) = self.get(path) {
            if existing.shared.read().unwrap().soft_deleted {
                return Ok(CreateResult::Conflict);
            }
            return Ok(if config_matches(&existing, &config) {
                CreateResult::Exists(existing)
            } else {
                CreateResult::Conflict
            });
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
        let (deletion_tx, _) = watch::channel(false);
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
            fenced: AtomicBool::new(false),
            inflight_appends: AtomicUsize::new(0),
            inflight_appends_zero: tokio::sync::Notify::new(),
            retirement_state: StdMutex::new(crate::retirement::RetirementState::default()),
            deletion_tx,
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
        match self.streams.entry(path.to_string()) {
            Entry::Occupied(e) => {
                // Lost a race; compare against the winner.
                let existing = e.get().clone();
                let fp = state.file_path.clone();
                let _ = std::fs::remove_file(fp);
                if existing.shared.read().unwrap().soft_deleted {
                    return Ok(CreateResult::Conflict);
                }
                Ok(if config_matches(&existing, &state.config) {
                    CreateResult::Exists(existing)
                } else {
                    CreateResult::Conflict
                })
            }
            Entry::Vacant(v) => {
                v.insert(state.clone());
                // Take the fork reference only once insertion has succeeded, so
                // rejected/raced creates never leak a refcount on the source.
                let created = (|| -> std::io::Result<()> {
                    if let Some(p) = &parent {
                        p.shared.write().unwrap().ref_count += 1;
                        if let Err(e) = write_meta_sync(p, true) {
                            p.shared.write().unwrap().ref_count -= 1;
                            return Err(e);
                        }
                    }
                    if let Err(e) = write_meta_sync(&state, true) {
                        if let Some(p) = &parent {
                            p.shared.write().unwrap().ref_count -= 1;
                            let _ = write_meta_sync(p, true);
                        }
                        return Err(e);
                    }
                    Ok(())
                })();
                if let Err(e) = created {
                    // UNDO the create: without a durable sidecar the stream must
                    // not stay live — WAL mode would happily ack appends to it,
                    // and the next boot would treat the sidecar-less data file as
                    // an orphan and delete it (acked appends destroyed after a
                    // create the client saw fail).
                    self.streams
                        .remove_if(&state.path, |_, cur| Arc::ptr_eq(cur, &state));
                    let _ = std::fs::remove_file(&state.file_path);
                    return Err(e);
                }
                self.publish_inventory(&state);
                Ok(CreateResult::Created(state))
            }
        }
    }
}

#[cfg(test)]
static DELETE_FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
#[cfg(test)]
pub(crate) static DELETE_FAULT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn config_matches(existing: &StreamState, requested: &StreamConfig) -> bool {
    let ex = &existing.config;
    let closed_now = existing.shared.read().unwrap().closed;
    media_type(&ex.content_type) == media_type(&requested.content_type)
        && ex.ttl_seconds == requested.ttl_seconds
        && ex.expires_at_raw == requested.expires_at_raw
        && ex.forked_from == requested.forked_from
        && ex.fork_offset_raw == requested.fork_offset_raw
        && ex.fork_sub_offset.unwrap_or(0) == requested.fork_sub_offset.unwrap_or(0)
        // PUT without Stream-Closed against a closed stream is a conflict.
        && (requested.create_closed == closed_now)
}

#[cfg(test)]
mod expiry_deadline_tests {
    use super::*;

    fn config(ttl_seconds: Option<u64>, expires_at: Option<SystemTime>) -> StreamConfig {
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

    fn state(config: StreamConfig) -> (PathBuf, Arc<StreamState>) {
        let directory = std::env::temp_dir().join(format!(
            "ds-expiry-deadline-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store =
            Store::new_with_tier(directory.clone(), crate::tier::TierConfig::default()).unwrap();
        let state = match store.create("stream", config, None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        (directory, state)
    }

    fn set_last_access(state: &StreamState, last_access: SystemTime) {
        state.shared.write().unwrap().last_access = last_access;
    }

    #[test]
    fn expiry_deadline_no_policy() {
        let (directory, state) = state(config(None, None));

        assert_eq!(state.expiry_deadline(), None);
        assert!(!state.is_expired_at(UNIX_EPOCH));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_deadline_absolute_before_exact_after() {
        let deadline = UNIX_EPOCH + Duration::from_secs(100);
        let (directory, state) = state(config(None, Some(deadline)));

        assert_eq!(state.expiry_deadline(), Some(deadline));
        assert!(!state.is_expired_at(deadline - Duration::from_secs(1)));
        assert!(!state.is_expired_at(deadline));
        assert!(state.is_expired_at(deadline + Duration::from_secs(1)));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_deadline_ttl_before_exact_after() {
        let last_access = UNIX_EPOCH + Duration::from_secs(100);
        let deadline = last_access + Duration::from_secs(10);
        let (directory, state) = state(config(Some(10), None));
        set_last_access(&state, last_access);

        assert_eq!(state.expiry_deadline(), Some(deadline));
        assert!(!state.is_expired_at(deadline - Duration::from_secs(1)));
        assert!(!state.is_expired_at(deadline));
        assert!(state.is_expired_at(deadline + Duration::from_secs(1)));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_deadline_pre_epoch_last_access() {
        let last_access = UNIX_EPOCH.checked_sub(Duration::from_secs(10)).unwrap();
        let deadline = UNIX_EPOCH.checked_sub(Duration::from_secs(5)).unwrap();
        let (directory, state) = state(config(Some(5), None));
        set_last_access(&state, last_access);

        assert_eq!(state.expiry_deadline(), Some(deadline));
        assert!(!state.is_expired_at(deadline));
        assert!(state.is_expired_at(UNIX_EPOCH));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_deadline_ttl_overflow_is_not_finite() {
        let (directory, state) = state(config(Some(u64::MAX), None));
        set_last_access(&state, UNIX_EPOCH);

        assert_eq!(state.expiry_deadline(), None);
        assert!(!state.is_expired_at(UNIX_EPOCH));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_deadline_earlier_ttl_wins_when_config_contains_both_policies() {
        let absolute = UNIX_EPOCH + Duration::from_secs(100);
        let ttl_deadline = UNIX_EPOCH + Duration::from_secs(1);
        let (directory, state) = state(config(Some(1), Some(absolute)));
        set_last_access(&state, UNIX_EPOCH);

        assert_eq!(state.expiry_deadline(), Some(ttl_deadline));
        assert!(state.is_expired_at(UNIX_EPOCH + Duration::from_secs(2)));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn expiry_deadline_earlier_absolute_wins_when_config_contains_both_policies() {
        let absolute = UNIX_EPOCH + Duration::from_secs(1);
        let (directory, state) = state(config(Some(100), Some(absolute)));
        set_last_access(&state, UNIX_EPOCH);

        assert_eq!(state.expiry_deadline(), Some(absolute));
        assert!(state.is_expired_at(UNIX_EPOCH + Duration::from_secs(2)));

        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod stream_lifecycle_tests {
    use super::*;
    use tokio::time::timeout;

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

    fn temporary_directory(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "ds-stream-lifecycle-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn create_state() -> (PathBuf, Store, Arc<StreamState>) {
        let directory = temporary_directory("create");
        let store =
            Store::new_with_tier(directory.clone(), crate::tier::TierConfig::default()).unwrap();
        let state = match store.create("stream", config(), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        (directory, store, state)
    }

    #[test]
    fn stream_lifecycle_create_initializes_transient_state() {
        fn assert_send<T: Send>() {}

        assert_send::<InflightAppendGuard>();
        let (directory, _store, state) = create_state();

        assert!(!state.fenced.load(Ordering::Acquire));
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 0);
        assert!(state.retirement_state().is_clean());
        assert!(!*state.subscribe_deletion().borrow());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn stream_lifecycle_recovery_reinitializes_transient_state() {
        let directory = temporary_directory("recovery");
        let store =
            Store::new_with_tier(directory.clone(), crate::tier::TierConfig::default()).unwrap();
        let state = match store.create("stream", config(), None, 0).unwrap() {
            CreateResult::Created(state) => state,
            _ => panic!("expected new stream"),
        };
        state.fenced.store(true, Ordering::Release);
        state.inflight_appends.store(2, Ordering::Release);
        let _ = state.retirement_state().reserve(std::time::Instant::now());
        state.signal_deletion();
        drop(state);
        drop(store);

        let recovered_store =
            Store::new_with_tier(directory.clone(), crate::tier::TierConfig::default()).unwrap();
        let recovered = recovered_store.get("stream").expect("recovered stream");
        assert!(!recovered.fenced.load(Ordering::Acquire));
        assert_eq!(recovered.inflight_appends.load(Ordering::Acquire), 0);
        assert!(recovered.retirement_state().is_clean());
        assert!(!*recovered.subscribe_deletion().borrow());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_lifecycle_guard_count_and_final_drop_notifies() {
        let (directory, _store, state) = create_state();
        let appender = state.appender.lock().await;
        let first = InflightAppendGuard::begin(&state, &appender).expect("unfenced stream");
        let second = InflightAppendGuard::begin(&state, &appender).expect("unfenced stream");
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 2);

        let waiting_state = state.clone();
        let waiter = tokio::spawn(async move {
            waiting_state.wait_for_inflight_appends_zero().await;
        });
        tokio::task::yield_now().await;

        drop(first);
        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 1);
        assert!(!waiter.is_finished());
        drop(second);
        timeout(Duration::from_secs(5), waiter)
            .await
            .expect("final drop must wake waiter")
            .unwrap();

        drop(appender);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_lifecycle_guard_drops_on_early_return() {
        let (directory, _store, state) = create_state();
        let appender = state.appender.lock().await;

        let begin_then_return = || {
            let _guard = InflightAppendGuard::begin(&state, &appender).expect("unfenced stream");
        };
        begin_then_return();

        assert_eq!(state.inflight_appends.load(Ordering::Acquire), 0);
        drop(appender);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_lifecycle_fence_under_appender_lock_rejects_later_guard() {
        let (directory, _store, state) = create_state();
        let appender = state.appender.lock().await;

        state.fence_while_holding_appender(&appender);
        assert!(InflightAppendGuard::begin(&state, &appender).is_none());

        drop(appender);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_lifecycle_wait_registration_drop_interleaving_completes() {
        let (directory, _store, state) = create_state();
        let appender = state.appender.lock().await;
        let guard = InflightAppendGuard::begin(&state, &appender).expect("unfenced stream");
        let waiting_state = state.clone();
        let waiter = tokio::spawn(async move {
            waiting_state.wait_for_inflight_appends_zero().await;
        });

        tokio::task::yield_now().await;
        drop(guard);
        timeout(Duration::from_secs(5), waiter)
            .await
            .expect("registered waiter must not miss final drop")
            .unwrap();

        drop(appender);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_lifecycle_deletion_watch_is_level_triggered() {
        let (directory, _store, state) = create_state();
        let mut before_signal = state.subscribe_deletion();
        assert!(!*before_signal.borrow());

        state.signal_deletion();
        before_signal.changed().await.unwrap();
        assert!(*before_signal.borrow());
        assert!(*state.subscribe_deletion().borrow());

        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod retirement_executor_lifecycle_tests {
    use super::*;
    use crate::retirement::{LogicalCompletion, TerminalCleanupCompletion};

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

    fn temporary_store(tag: &str) -> (PathBuf, Arc<Store>) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ds-retirement-executor-lifecycle-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let store = Arc::new(
            Store::new_with_tier(directory.clone(), crate::tier::TierConfig::default()).unwrap(),
        );
        (directory, store)
    }

    async fn wait_until_fenced(stream: &StreamState) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !stream.fenced.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("explicit retirement should fence the admitted stream");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_executor_lifecycle_initializes_once_and_shuts_down_workers() {
        let (directory, store) = temporary_store("once");
        let executor = Arc::clone(
            store
                .init_retirement_executor()
                .expect("first initialization succeeds"),
        );
        assert!(Arc::ptr_eq(
            &executor,
            store
                .retirement_executor()
                .expect("initialized executor is accessible")
        ));
        let second_initialization = match store.init_retirement_executor() {
            Ok(_) => panic!("second initialization must fail"),
            Err(error) => error,
        };
        assert_eq!(
            second_initialization.kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert!(executor.worker_count() > 0);
        executor.shutdown().await;
        assert_eq!(executor.worker_count(), 0);

        drop(executor);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_executor_lifecycle_callback_cleans_the_exact_stream() {
        let (directory, store) = temporary_store("callback");
        store.init_retirement_executor().unwrap();
        let stream = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected stream creation"),
        };
        let ticket = match store.retire_explicit(stream.clone()).await {
            ExplicitRetirementResult::Owner(ticket) => ticket,
            _ => panic!("first explicit retirement owns the logical gate"),
        };
        assert!(matches!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        assert!(!stream.file_path.exists());
        store.retirement_executor().unwrap().shutdown().await;

        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_executor_lifecycle_weak_callback_does_not_retain_store() {
        let (directory, store) = temporary_store("weak");
        let executor = Arc::clone(store.init_retirement_executor().unwrap());
        let weak_store = Arc::downgrade(&store);

        drop(store);
        assert!(
            weak_store.upgrade().is_none(),
            "the executor callback must not retain Store"
        );
        executor.shutdown().await;
        drop(executor);
        assert!(weak_store.upgrade().is_none());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_retirement_store_waits_for_inflight_and_deduplicates() {
        let (directory, store) = temporary_store("inflight");
        store.init_retirement_executor().unwrap();
        let stream = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected stream creation"),
        };
        let appender = stream.appender.lock().await;
        let guard = InflightAppendGuard::begin(&stream, &appender).unwrap();
        drop(appender);

        let owner_store = store.clone();
        let owner_stream = stream.clone();
        let mut owner =
            tokio::spawn(async move { owner_store.retire_explicit(owner_stream).await });
        wait_until_fenced(&stream).await;
        let duplicate = match store.retire_explicit(stream.clone()).await {
            ExplicitRetirementResult::Existing(ticket) => ticket,
            _ => panic!("duplicate must share the admitted ticket"),
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut owner)
                .await
                .is_err(),
            "logical retirement and cleanup must wait for the full-ack guard"
        );
        assert!(stream.file_path.exists());

        drop(guard);
        let ticket = match tokio::time::timeout(Duration::from_secs(5), &mut owner)
            .await
            .expect("retirement resumes after final guard drop")
            .expect("retirement task should not panic")
        {
            ExplicitRetirementResult::Owner(ticket) => ticket,
            _ => panic!("admitted caller must own Store linearization"),
        };
        assert!(ticket.same_identity(&duplicate));
        assert_eq!(ticket.wait_logical().await, LogicalCompletion::Completed);
        assert!(store.streams.get("stream").is_none());
        assert!(!store
            .inventory_page(None, None, 10)
            .unwrap()
            .1
            .iter()
            .any(|entry| entry.path == "stream"));
        assert!(matches!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        store.retirement_executor().unwrap().shutdown().await;

        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_retirement_store_soft_tombstone_is_durable() {
        let (directory, store) = temporary_store("soft");
        store.init_retirement_executor().unwrap();
        let stream = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected stream creation"),
        };
        stream.shared.write().unwrap().ref_count = 1;
        let ticket = match store.retire_explicit(stream.clone()).await {
            ExplicitRetirementResult::Owner(ticket) => ticket,
            _ => panic!("soft retirement should own linearization"),
        };
        assert_eq!(ticket.wait_logical().await, LogicalCompletion::Completed);
        assert!(matches!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        let retained = store
            .get("stream")
            .expect("soft tombstone stays registered");
        assert!(retained.shared.read().unwrap().soft_deleted);
        store.retirement_executor().unwrap().shutdown().await;

        drop(retained);
        drop(stream);
        drop(store);
        let reopened = Store::new_with_tier(directory.clone(), crate::tier::TierConfig::default())
            .expect("durable soft tombstone reopens");
        assert!(
            reopened
                .get("stream")
                .expect("soft tombstone is recovered")
                .shared
                .read()
                .unwrap()
                .soft_deleted
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_retirement_store_replacement_cancels_the_owner_ticket() {
        let (directory, store) = temporary_store("replacement");
        store.init_retirement_executor().unwrap();
        let original = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected original stream"),
        };
        let appender = original.appender.lock().await;
        let guard = InflightAppendGuard::begin(&original, &appender).unwrap();
        drop(appender);
        let owner_store = store.clone();
        let owner_stream = original.clone();
        let owner = tokio::spawn(async move { owner_store.retire_explicit(owner_stream).await });
        wait_until_fenced(&original).await;

        store.streams.remove_if("stream", |_, current| {
            current.id == original.id && Arc::ptr_eq(current, &original)
        });
        let replacement = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected replacement stream"),
        };
        drop(guard);
        let ticket = match tokio::time::timeout(Duration::from_secs(5), owner)
            .await
            .expect("replacement race must resolve")
            .expect("retirement task should not panic")
        {
            ExplicitRetirementResult::Cancelled(ticket) => ticket,
            _ => panic!("lost identity must cancel the owner ticket"),
        };
        assert_eq!(ticket.wait_logical().await, LogicalCompletion::Cancelled);
        assert_eq!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Cancelled
        );
        assert!(Arc::ptr_eq(
            store.streams.get("stream").unwrap().value(),
            &replacement
        ));
        assert!(original.file_path.exists());
        assert!(replacement.file_path.exists());
        store.retirement_executor().unwrap().shutdown().await;

        drop(replacement);
        drop(original);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_retirement_store_rejects_unfenced_direct_cleanup() {
        let (directory, store) = temporary_store("unfenced");
        store.init_retirement_executor().unwrap();
        let stream = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected stream creation"),
        };
        assert!(store
            .finalize_retirement_cleanup(&stream, LocalCleanupMode::ExplicitDelete)
            .is_err());
        assert!(stream.file_path.exists());
        assert!(store.is_exact_registered(&stream));
        store.retirement_executor().unwrap().shutdown().await;

        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_retirement_store_retries_failed_hard_cleanup_without_unfencing() {
        let _fault_guard = DELETE_FAULT_LOCK.lock().await;
        let (directory, store) = temporary_store("retry");
        store.init_retirement_executor().unwrap();
        let stream = match store.create("stream", stream_config(), None, 0).unwrap() {
            CreateResult::Created(stream) => stream,
            _ => panic!("expected stream creation"),
        };
        DELETE_FAULT.store(2, Ordering::Relaxed);
        let ticket = match store.retire_explicit(stream.clone()).await {
            ExplicitRetirementResult::Owner(ticket) => ticket,
            _ => panic!("hard retirement should own linearization"),
        };
        assert_eq!(
            ticket.wait_first_attempt().await,
            crate::retirement::FirstAttemptCompletion::Failed
        );
        assert!(stream.fenced.load(Ordering::Acquire));
        assert!(stream.file_path.exists());
        assert!(store.streams.get("stream").is_none());

        DELETE_FAULT.store(0, Ordering::Relaxed);
        assert!(matches!(
            ticket.wait_terminal().await,
            TerminalCleanupCompletion::Succeeded { .. }
        ));
        store.retirement_executor().unwrap().shutdown().await;

        drop(stream);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }
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
    // Serialize per stream so concurrent writers don't race on the temp file or
    // reorder renames (a stale flush must not clobber a durable manifest flip).
    let _g = st.meta_lock.lock().unwrap_or_else(|e| e.into_inner());
    let meta = Meta::capture(st);
    let bytes = serde_json::to_vec(&meta).expect("meta serializes");
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
        let _fault_guard = DELETE_FAULT_LOCK.lock().await;
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
        store.delete_or_soft_delete_durable(&st).unwrap();

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
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
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
        let _fault_guard = DELETE_FAULT_LOCK.lock().await;
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
        let _fault_guard = DELETE_FAULT_LOCK.blocking_lock();
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
    fn expiry_keeps_inventory_until_local_unlink_succeeds() {
        let _fault_guard = DELETE_FAULT_LOCK.blocking_lock();
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

    #[test]
    fn inventory_identity_stale_state_cannot_publish_or_remove_replacement() {
        let _fault_guard = DELETE_FAULT_LOCK.blocking_lock();
        let dir = tmp_dir("identity-replacement");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let old = create(&store, "same");
        let old_id = old.id;
        store.streams.remove_if("same", |_, current| {
            current.id == old.id && Arc::ptr_eq(current, &old)
        });
        let replacement = create(&store, "same");
        let (generation, entries, _) = store.inventory_page(None, None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].stream_id, replacement.id);

        store.publish_inventory_tail(&old);
        assert_eq!(store.inventory_page(None, None, 10).unwrap().0, generation);

        store.delete_or_soft_delete_durable(&old).unwrap();
        let (after_delete, entries, _) = store.inventory_page(None, None, 10).unwrap();
        assert_eq!(after_delete, generation, "identity mismatch is a no-op");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "same");
        assert_eq!(entries[0].stream_id, replacement.id);
        assert_ne!(old_id, replacement.id);
        assert!(replacement.file_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn physical_cleanup_reclaims_exact_local_bytes_and_is_idempotent() {
        let _fault_guard = DELETE_FAULT_LOCK.blocking_lock();
        let dir = tmp_dir("cleanup-bytes");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let st = create(&store, "bytes");
        std::fs::write(&st.file_path, b"data-file").unwrap();
        let meta = meta_path(&st.file_path);
        let segment_dir = store.segments_dir();
        std::fs::create_dir_all(&segment_dir).unwrap();
        let segment = segment_dir.join(format!(
            "{}.seg.0000000000000000",
            st.file_path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&segment, b"staged-segment").unwrap();
        let expected = std::fs::metadata(&st.file_path).unwrap().len()
            + std::fs::metadata(&meta).unwrap().len()
            + std::fs::metadata(&segment).unwrap().len();

        let outcome = store
            .cleanup_local_stream(&st, LocalCleanupMode::ExplicitDelete)
            .unwrap();
        assert_eq!(outcome.reclaimed_local_bytes, expected);
        assert!(!st.file_path.exists());
        assert!(!meta.exists());
        assert!(!segment.exists());
        assert_eq!(
            store
                .cleanup_local_stream(&st, LocalCleanupMode::ExplicitDelete)
                .unwrap()
                .reclaimed_local_bytes,
            0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn physical_cleanup_explicit_sync_failure_retains_inventory_until_retry() {
        let _fault_guard = DELETE_FAULT_LOCK.blocking_lock();
        let dir = tmp_dir("cleanup-sync-failure");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let st = create(&store, "sync");
        DELETE_FAULT.store(3, Ordering::Relaxed);
        assert!(store.delete_or_soft_delete_durable(&st).is_err());
        assert!(store.get("sync").is_some());
        assert!(store
            .inventory_page(None, None, 10)
            .unwrap()
            .1
            .iter()
            .any(|entry| entry.path == "sync"));

        assert!(store.delete_or_soft_delete_durable(&st).is_err());
        assert!(store
            .inventory_page(None, None, 10)
            .unwrap()
            .1
            .iter()
            .any(|entry| entry.path == "sync"));
        DELETE_FAULT.store(0, Ordering::Relaxed);
        store.delete_or_soft_delete_durable(&st).unwrap();
        assert!(store.get("sync").is_none());
        assert!(!store
            .inventory_page(None, None, 10)
            .unwrap()
            .1
            .iter()
            .any(|entry| entry.path == "sync"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn physical_cleanup_expiry_propagates_io_and_skips_directory_sync() {
        let _fault_guard = DELETE_FAULT_LOCK.blocking_lock();
        let dir = tmp_dir("cleanup-expiry");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let failing = create(&store, "failing");
        DELETE_FAULT.store(2, Ordering::Relaxed);
        assert!(store
            .cleanup_local_stream(&failing, LocalCleanupMode::Expiry)
            .is_err());
        assert!(failing.file_path.exists());
        DELETE_FAULT.store(0, Ordering::Relaxed);

        let expiry = create(&store, "expiry");
        DELETE_FAULT.store(3, Ordering::Relaxed);
        let outcome = store
            .cleanup_local_stream(&expiry, LocalCleanupMode::Expiry)
            .unwrap();
        DELETE_FAULT.store(0, Ordering::Relaxed);
        assert!(outcome.reclaimed_local_bytes > 0);
        assert!(!expiry.file_path.exists());
        assert!(!meta_path(&expiry.file_path).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn physical_cleanup_soft_delete_reclaims_no_local_bytes() {
        let _fault_guard = DELETE_FAULT_LOCK.blocking_lock();
        let dir = tmp_dir("cleanup-soft");
        let store = Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap();
        let st = create(&store, "soft");
        st.shared.write().unwrap().ref_count = 1;

        assert_eq!(
            store
                .delete_or_soft_delete_durable(&st)
                .unwrap()
                .reclaimed_local_bytes,
            0
        );
        assert!(st.file_path.exists());
        assert!(store
            .inventory_page(None, None, 10)
            .unwrap()
            .1
            .iter()
            .any(|entry| entry.path == "soft" && entry.deleted));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
