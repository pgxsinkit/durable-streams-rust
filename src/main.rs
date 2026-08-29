mod admin_readiness;
mod api;
mod blobstore;
mod data_dir_lock;
mod engine_raw;
mod handlers;
mod http1;
mod reserved_paths;
mod retirement;
mod srvstats;
#[cfg(target_os = "linux")]
mod sse_reactor;
mod store;
mod store_manifest;
mod subscriptions;
mod telemetry;
mod tier;
mod wal;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;

use store::Store;

const DEFAULT_MINIMUM_FREE_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const DEFAULT_MINIMUM_FREE_INODES: u64 = 10_000;

fn exit_usage(message: impl std::fmt::Display) -> ! {
    eprintln!("error: {message}");
    std::process::exit(2)
}

fn bootstrap_store(args: &[String]) -> ! {
    let mut values = std::collections::HashMap::<&str, String>::new();
    let allowed = [
        "--data-dir",
        "--store-id",
        "--store-generation",
        "--protocol-version",
        "--layout-version",
        "--durability-mode",
        "--wal-shards",
        "--stream-lanes",
        "--filesystem-uuid",
        "--creation-time",
    ];
    let mut index = 0;
    while index < args.len() {
        let flag = &args[index];
        if !allowed.contains(&flag.as_str()) {
            exit_usage(format!("bootstrap-store unknown argument: {flag}"));
        }
        index += 1;
        let Some(value) = args.get(index) else {
            exit_usage(format!("{flag} requires a value"));
        };
        if values.insert(flag, value.clone()).is_some() {
            exit_usage(format!("bootstrap-store duplicate argument: {flag}"));
        }
        index += 1;
    }
    let required = |flag: &str| {
        values
            .get(flag)
            .cloned()
            .unwrap_or_else(|| exit_usage(format!("bootstrap-store requires {flag}")))
    };
    let data_dir: std::path::PathBuf = required("--data-dir").into();
    let parse = |flag: &str| {
        required(flag)
            .parse::<u32>()
            .unwrap_or_else(|_| exit_usage(format!("{flag} must be an unsigned 32-bit integer")))
    };
    let manifest = store_manifest::StoreManifestV1 {
        store_id: required("--store-id"),
        store_generation: required("--store-generation"),
        protocol_version: parse("--protocol-version"),
        layout_version: parse("--layout-version"),
        durability_mode: required("--durability-mode"),
        wal_shard_count: parse("--wal-shards"),
        stream_lane_count: parse("--stream-lanes"),
        filesystem_uuid: required("--filesystem-uuid"),
        creation_time: required("--creation-time"),
    };
    let _lock = data_dir_lock::DataDirLock::acquire(&data_dir).unwrap_or_else(|e| exit_usage(e));
    store_manifest::create_atomically(&data_dir, &manifest).unwrap_or_else(|e| exit_usage(e));
    println!(
        "bootstrapped Durable Streams store at {}",
        data_dir.display()
    );
    std::process::exit(0)
}

fn valid_artifact_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Take a flag's value or exit(2) with a clean usage error (not a panic).
fn val(o: Option<String>, flag: &str) -> String {
    o.unwrap_or_else(|| {
        eprintln!("error: {flag} requires a value");
        std::process::exit(2);
    })
}

/// Parse a flag's value or exit(2) with a clean error.
fn parse_val<T: std::str::FromStr>(o: Option<String>, flag: &str) -> T {
    let s = val(o, flag);
    s.parse().unwrap_or_else(|_| {
        eprintln!("error: {flag} got an invalid value: {s:?}");
        std::process::exit(2);
    })
}

/// True if `<data_dir>/wal` holds a `*.wal` segment that contains at least one
/// RECORD (`wal/<shard>/*.wal` layout, or directly under `wal/`). Used to fail
/// fast when `--durability memory` is pointed at a data dir left behind by a
/// previous `--durability wal` run — memory mode never opens/replays a WAL, so it
/// would silently ignore those records (and drop any not yet folded into the
/// per-stream files). A clean rejection beats a silent divergence.
///
/// A segment with a record begins with a non-zero header (`[0..4)` framed `len`,
/// `[8..16)` `lsn ≥ 1`); a fresh/`fallocate`-zeroed segment reads as all-zero. We
/// therefore ignore empty (never-written or reset) segments — but this is
/// FAIL-CLOSED: records that were already checkpointed into the per-stream files
/// still physically occupy the segment until the next startup recycles it, so
/// this can over-report (reject a dir that is actually safe), never under-report.
fn wal_dir_has_segments(wal_dir: &std::path::Path) -> bool {
    // A segment holds a record iff its first 16 header bytes are not all zero.
    fn has_record(path: &std::path::Path) -> bool {
        use std::io::Read;
        let Ok(mut f) = std::fs::File::open(path) else {
            return false;
        };
        let mut hdr = [0u8; 16];
        matches!(f.read_exact(&mut hdr), Ok(())) && hdr != [0u8; 16]
    }
    let is_wal = |p: &std::path::Path| p.extension().and_then(|e| e.to_str()) == Some("wal");
    let Ok(entries) = std::fs::read_dir(wal_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if is_wal(&path) && has_record(&path) {
            return true;
        }
        if path.is_dir() {
            if let Ok(inner) = std::fs::read_dir(&path) {
                for e in inner.flatten() {
                    let p = e.path();
                    if is_wal(&p) && has_record(&p) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Raise the open-file-descriptor soft limit to the hard limit at startup. Each
/// connection costs ≥1 fd (plus per-stream data-file fds), so the default soft
/// limit (commonly 1024) caps concurrency far below what the server can handle
/// and makes `accept()` fail with EMFILE under load. Best-effort: errors are
/// ignored (the accept loop also backs off on EMFILE as a safety net).
#[cfg(unix)]
fn raise_nofile_limit() {
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        // macOS rejects RLIM_INFINITY for NOFILE (and caps at kern.maxfilesperproc);
        // pick a high concrete target so the raise succeeds across platforms.
        let target = if lim.rlim_max == libc::RLIM_INFINITY {
            1_048_576
        } else {
            lim.rlim_max
        };
        if lim.rlim_cur < target {
            lim.rlim_cur = target;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}

fn main() {
    #[cfg(unix)]
    raise_nofile_limit();
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args
        .first()
        .is_some_and(|argument| argument == "bootstrap-store")
    {
        bootstrap_store(&raw_args[1..]);
    }
    let mut port: u16 = 4437; // protocol default (PROTOCOL.md §13.1)
    let mut host: std::net::IpAddr = [127, 0, 0, 1].into();
    let mut data_dir = std::env::temp_dir().join("durable-streams-rust");
    // Whether `--data-dir` was NAMED, not what it resolved to. `--durability wal` requires it
    // (see the guard below): the default is a temp dir, and wal into a directory that does not
    // survive a restart is the one durability misconfiguration that leaves no trace — every
    // fsync is performed and every byte is discarded. Whether a path persists is not knowable
    // from its spelling (a bind-mounted /tmp does; a tmpfs /var/lib does not), so the question
    // asked is the answerable one: did an operator choose this directory on purpose.
    let mut data_dir_explicit = false;
    let mut tier = tier::TierConfig::default();
    // `--wal-shards N` (the WAL shard count). `None` ⇒ on a fresh data dir use the
    // core count; on an existing one reuse the persisted N. A value ≠ the persisted
    // N is rejected with exit 2 (spec §5).
    let mut wal_shards: Option<usize> = None;
    // `--worker-threads N` sizes the tokio runtime's worker-thread pool (and the
    // default WAL shard count). `None` ⇒ `available_parallelism()`. This is
    // load-bearing under a cgroup cpu limit: `available_parallelism()` reads
    // `cpu.max`, so on a big node with a small limit it would under-size the pool;
    // an explicit value (e.g. the ds-bench pool suites' `--worker-threads 32`)
    // pins the pool to the intended core count regardless.
    let mut worker_threads: Option<usize> = None;
    // `--wal-segment-bytes N` overrides the per-shard WAL segment size (the
    // `fallocate` size + segment-roll threshold). `None` ⇒ the 128 MiB default.
    // Useful for forcing rolls in tests and benches without writing a full 128 MiB segment.
    let mut wal_segment_bytes: Option<u64> = None;
    // `--wal-stats N`: every N seconds print a `WAL_CONT` line of per-interval WAL
    // contention rates (lock-wait, wakeup fan-out, coalescing) to stderr, and arm
    // the hot-path timing that feeds it. OFF by default (no clock reads on the
    // append path). Dependency-free — the measurement vehicle for the contention
    // investigation, independent of the heavy `telemetry` OTLP feature.
    let mut wal_stats_secs: Option<u64> = None;
    let mut server_stats_secs: Option<u64> = None;
    let mut expected_store_id: Option<String> = None;
    let mut expected_store_generation: Option<String> = None;
    let mut expected_protocol_version: Option<u32> = None;
    let mut expected_layout_version: Option<u32> = None;
    let mut expected_filesystem_uuid: Option<String> = None;
    let mut artifact_digest: Option<String> = None;
    let mut minimum_free_bytes = DEFAULT_MINIMUM_FREE_BYTES;
    let mut minimum_free_inodes = DEFAULT_MINIMUM_FREE_INODES;
    let mut stream_lanes: Option<u32> = None;
    let mut args = raw_args.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => host = parse_val(args.next(), "--host"),
            "--port" => port = parse_val(args.next(), "--port"),
            "--data-dir" => {
                data_dir = val(args.next(), "--data-dir").into();
                data_dir_explicit = true;
            }
            "--store-id" => expected_store_id = Some(val(args.next(), "--store-id")),
            "--store-generation" => {
                expected_store_generation = Some(val(args.next(), "--store-generation"))
            }
            "--protocol-version" => {
                expected_protocol_version = Some(parse_val(args.next(), "--protocol-version"))
            }
            "--layout-version" => {
                expected_layout_version = Some(parse_val(args.next(), "--layout-version"))
            }
            "--filesystem-uuid" => {
                expected_filesystem_uuid = Some(val(args.next(), "--filesystem-uuid"))
            }
            "--artifact-digest" => artifact_digest = Some(val(args.next(), "--artifact-digest")),
            "--minimum-free-bytes" => {
                minimum_free_bytes = parse_val(args.next(), "--minimum-free-bytes")
            }
            "--minimum-free-inodes" => {
                minimum_free_inodes = parse_val(args.next(), "--minimum-free-inodes")
            }
            "--long-poll-timeout-ms" => {
                handlers::set_long_poll_timeout(parse_val(args.next(), "--long-poll-timeout-ms"));
            }
            // Resident tail-cache cap (bytes); 0 disables it (reads → sendfile/pread).
            // Default is platform-dependent (off on Linux, 64 KiB on macOS).
            "--tail-cache-bytes" => {
                store::set_tail_cache_bytes(parse_val(args.next(), "--tail-cache-bytes"));
            }
            "--read-offload" => {
                let v = val(args.next(), "--read-offload");
                match engine_raw::ReadOffload::parse(&v) {
                    Some(mode) => engine_raw::set_read_offload(mode),
                    None => {
                        eprintln!("--read-offload must be inline|tail|always");
                        std::process::exit(2);
                    }
                }
            }
            // ---- hot/cold tiering (OFF by default) ----
            "--tier" => {
                let v = val(args.next(), "--tier");
                tier.kind = match v.as_str() {
                    "off" => tier::TierKind::Off,
                    "s3" => tier::TierKind::S3,
                    _ => {
                        eprintln!("--tier must be off|s3");
                        std::process::exit(2);
                    }
                };
            }
            "--tier-segment-bytes" => {
                tier.segment_bytes = parse_val(args.next(), "--tier-segment-bytes");
            }
            "--tier-compact-bytes" => {
                tier.compact_bytes = parse_val(args.next(), "--tier-compact-bytes");
            }
            "--tier-key-prefix" => tier.key_prefix = val(args.next(), "--tier-key-prefix"),
            "--tier-endpoint" => tier.endpoint = Some(val(args.next(), "--tier-endpoint")),
            "--tier-region" => tier.region = Some(val(args.next(), "--tier-region")),
            "--tier-bucket" => tier.bucket = Some(val(args.next(), "--tier-bucket")),
            "--tier-path-style" => {
                tier.path_style = true;
            }
            "--tier-virtual-hosted" => {
                tier.path_style = false;
            }
            "--tier-allow-http" => {
                tier.allow_http = true;
            }
            "--wal-shards" => {
                let n: usize = parse_val(args.next(), "--wal-shards");
                if n == 0 {
                    eprintln!("--wal-shards must be ≥ 1");
                    std::process::exit(2);
                }
                wal_shards = Some(n);
            }
            "--worker-threads" => {
                let n: usize = parse_val(args.next(), "--worker-threads");
                if n == 0 {
                    eprintln!("--worker-threads must be ≥ 1");
                    std::process::exit(2);
                }
                worker_threads = Some(n);
            }
            "--wal-segment-bytes" => {
                let n: u64 = parse_val(args.next(), "--wal-segment-bytes");
                if n == 0 {
                    eprintln!("--wal-segment-bytes must be ≥ 1");
                    std::process::exit(2);
                }
                wal_segment_bytes = Some(n);
            }
            "--wal-stats" => {
                let n: u64 = parse_val(args.next(), "--wal-stats");
                if n == 0 {
                    eprintln!("--wal-stats must be ≥ 1 (seconds)");
                    std::process::exit(2);
                }
                wal_stats_secs = Some(n);
            }
            "--durability" => {
                let v = val(args.next(), "--durability");
                match handlers::parse_durability(&v) {
                    Some(m) => handlers::set_durability(m),
                    None => {
                        eprintln!("--durability must be wal|memory");
                        std::process::exit(2);
                    }
                }
            }
            // Periodic SRV_STATS line (both modes): cpu_cores / inflight / service
            // + appender-lock + durability wait — bottleneck analysis.
            "--server-stats" => {
                let n: u64 = parse_val(args.next(), "--server-stats");
                if n == 0 {
                    eprintln!("--server-stats must be ≥ 1 (seconds)");
                    std::process::exit(2);
                }
                server_stats_secs = Some(n);
            }
            // Checkpoint time trigger: per-shard cadence in ms (default 3000).
            "--wal-checkpoint-interval-ms" => {
                let v = val(args.next(), "--wal-checkpoint-interval-ms");
                match v.parse::<u64>() {
                    Ok(ms) if ms >= 1 => wal::shard::set_checkpoint_interval_ms(ms),
                    _ => {
                        eprintln!("--wal-checkpoint-interval-ms must be a positive integer (milliseconds)");
                        std::process::exit(2);
                    }
                }
            }
            // Stream data lanes: hash stream files across streams/<0..N>/ subdirs,
            // one per (intended) device, so checkpoint writeback spreads over N
            // devices with N parallel syncfs barriers (the ~1M-stream wall fix).
            // A LAYOUT choice: must match the on-disk layout across restarts.
            "--stream-lanes" => {
                let v = val(args.next(), "--stream-lanes");
                match v.parse::<usize>() {
                    Ok(n) if n >= 1 && u32::try_from(n).is_ok() => {
                        store::set_stream_lanes(n);
                        stream_lanes = Some(n as u32);
                    }
                    _ => {
                        eprintln!("--stream-lanes must be a positive integer");
                        std::process::exit(2);
                    }
                }
            }
            // Checkpoint size trigger: checkpoint a shard as soon as its retained
            // WAL exceeds this many bytes (0 = disabled). An explicit replay-time
            // budget that also self-staggers shards by their own write rates.
            "--wal-checkpoint-wal-bytes" => {
                let v = val(args.next(), "--wal-checkpoint-wal-bytes");
                match v.parse::<u64>() {
                    Ok(bytes) => wal::shard::set_checkpoint_wal_bytes(bytes),
                    _ => {
                        eprintln!(
                            "--wal-checkpoint-wal-bytes must be a non-negative integer (bytes)"
                        );
                        std::process::exit(2);
                    }
                }
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    // Apply --durability memory AFTER the arg loop. Memory mode is the buffered
    // append path with the WAL stage/wait skipped (no splice intercept, no forced
    // tail-cache-off — those belonged to the removed zero-copy path); the only
    // gate is refusing to silently ignore a WAL left by a previous wal run.
    if handlers::durability() == handlers::DurabilityMode::Memory {
        // Memory mode acks before anything is fsynced, so pairing it with a cold
        // tier would offload un-fsynced (loseable) data as if it were durable —
        // a combination with no coherent durability story. Refuse it.
        if tier.kind != tier::TierKind::Off {
            eprintln!("error: --durability memory cannot be combined with --tier (memory-mode acks are not durable; tiering presumes durable segments)");
            std::process::exit(2);
        }
        // Fail fast on a WAL left by a previous `--durability wal` run: memory mode
        // never opens/replays it, so starting here would silently ignore those
        // records (and drop any not yet folded into the per-stream files). Refuse
        // rather than diverge quietly; the operator can replay with `--durability
        // wal` first, or remove the `wal/` directory to discard it deliberately.
        let wal_dir = data_dir.join("wal");
        if wal_dir_has_segments(&wal_dir) {
            eprintln!(
                "error: --durability memory refuses to start: {} holds a WAL from a previous \
                 --durability wal run. Memory mode would ignore it and could drop un-checkpointed \
                 records. Replay it first with --durability wal, or remove {} to discard it.",
                wal_dir.display(),
                wal_dir.display()
            );
            std::process::exit(2);
        }
    }

    // The symmetric guard on the wal side. The two above refuse memory-mode configurations that
    // would silently IGNORE durable data; this one refuses a wal-mode configuration that would
    // silently FAIL TO PRODUCE any — `--durability wal` with a defaulted `--data-dir` writes its
    // WAL into a temp dir, so every append pays a real fdatasync and every byte is discarded on
    // the next container or machine restart. Nothing about a running server distinguishes that
    // from working durability: conformance passes, reads are correct, the acks are honest right
    // up until the restart. So it is refused at startup rather than discovered afterwards.
    //
    // The gate is whether the flag was NAMED, not where it points, so a throwaway directory
    // stays available to tests and benches that want the wal code path without persistence —
    // they just have to say so (the conformance harness already passes an explicit mkdtemp dir).
    if handlers::durability() == handlers::DurabilityMode::Wal && !data_dir_explicit {
        eprintln!(
            "error: --durability wal refuses to start without an explicit --data-dir. The default \
             ({}) is a temporary directory: every append would be fsynced and then discarded on \
             restart, with nothing to indicate durability was never real. Pass --data-dir <path> \
             on storage that persists, or use --durability memory if you do not need durability.",
            data_dir.display()
        );
        std::process::exit(2);
    }

    // WAL owns persistent state and therefore needs lifetime-exclusive access.
    // Memory mode intentionally retains its original shared/default-dir behavior.
    let data_dir_lock = if handlers::durability() == handlers::DurabilityMode::Wal {
        Some(data_dir_lock::DataDirLock::acquire(&data_dir).unwrap_or_else(|e| exit_usage(e)))
    } else {
        None
    };

    let manifest = if handlers::durability() == handlers::DurabilityMode::Wal {
        if minimum_free_bytes < DEFAULT_MINIMUM_FREE_BYTES
            || minimum_free_inodes < DEFAULT_MINIMUM_FREE_INODES
        {
            exit_usage(format!(
                "WAL pilot reserve cannot be lowered below {DEFAULT_MINIMUM_FREE_BYTES} bytes and {DEFAULT_MINIMUM_FREE_INODES} inodes"
            ));
        }
        if !host.is_loopback() {
            exit_usage("WAL pilot mode requires a loopback --host; DS-02 owns external access");
        }
        let expected = store_manifest::ExpectedStoreIdentityV1 {
            store_id: expected_store_id
                .unwrap_or_else(|| exit_usage("--store-id is required in WAL mode")),
            store_generation: expected_store_generation
                .unwrap_or_else(|| exit_usage("--store-generation is required in WAL mode")),
            protocol_version: expected_protocol_version
                .unwrap_or_else(|| exit_usage("--protocol-version is required in WAL mode")),
            layout_version: expected_layout_version
                .unwrap_or_else(|| exit_usage("--layout-version is required in WAL mode")),
            durability_mode: "wal".to_string(),
            wal_shard_count: u32::try_from(
                wal_shards.unwrap_or_else(|| exit_usage("--wal-shards is required in WAL mode")),
            )
            .unwrap_or_else(|_| exit_usage("--wal-shards exceeds u32")),
            stream_lane_count: stream_lanes
                .unwrap_or_else(|| exit_usage("--stream-lanes is required in WAL mode")),
            filesystem_uuid: expected_filesystem_uuid
                .unwrap_or_else(|| exit_usage("--filesystem-uuid is required in WAL mode")),
        };
        store_manifest::canonical_uuid("--store-id", &expected.store_id)
            .unwrap_or_else(|error| exit_usage(error));
        store_manifest::canonical_uuid("--store-generation", &expected.store_generation)
            .unwrap_or_else(|error| exit_usage(error));
        store_manifest::canonical_uuid("--filesystem-uuid", &expected.filesystem_uuid)
            .unwrap_or_else(|error| exit_usage(error));
        let manifest = store_manifest::read(&data_dir).unwrap_or_else(|error| exit_usage(error));
        manifest
            .compare_expected(&expected)
            .unwrap_or_else(|error| exit_usage(error));
        let digest = artifact_digest
            .as_deref()
            .unwrap_or_else(|| exit_usage("--artifact-digest is required in WAL mode"));
        if !valid_artifact_digest(digest) {
            exit_usage(
                "--artifact-digest must be lowercase sha256: followed by 64 hexadecimal digits",
            );
        }
        Some(manifest)
    } else {
        None
    };
    let readiness = manifest.map(|manifest| {
        Arc::new(admin_readiness::AdminReadiness::new(
            manifest,
            artifact_digest.expect("artifact digest required with a WAL manifest"),
            minimum_free_bytes,
            minimum_free_inodes,
        ))
    });

    // S3 credentials come from env (never CLI flags), matching the OTEL_*/AWS
    // convention. Honour both the DS_* names and the standard AWS_* fallbacks.
    if tier.kind == tier::TierKind::S3 {
        tier.access_key_id = std::env::var("DS_S3_ACCESS_KEY_ID")
            .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
            .ok();
        tier.secret_access_key = std::env::var("DS_S3_SECRET_ACCESS_KEY")
            .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
            .ok();
    }

    let workers = worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("failed to build runtime");

    rt.block_on(async move {
        // Hold the advisory lock until all runtime-owned store and WAL state is
        // drained.  Its drop at the end of this block is the release point.
        let _data_dir_lock = data_dir_lock;
        // Telemetry is OFF by default (feature-gated); a no-op unless built with
        // `--features telemetry`. Held across the run and flushed on Ctrl-C —
        // `serve()` never returns on its own.
        let mut telemetry_guard = telemetry::init();
        let store = Arc::new(
            Store::new_with_tier(data_dir.clone(), tier.clone()).expect("failed to init store"),
        );
        if handlers::durability() == handlers::DurabilityMode::Memory {
            store.refresh_inventory();
        }
        // Batched meta-sidecar sweeper (#4691): flushes every stream queued by
        // `Store::mark_meta_dirty` (memory-mode appends, TTL read touches) in
        // one pass per tick, replacing the per-stream 100 ms debounce timer.
        // Spawned in BOTH durability modes — wal mode still queues TTL read
        // touches here (its append path flushes via the checkpoint instead).
        spawn_meta_sweeper(Arc::clone(&store));

        // Server load telemetry (both modes) for bottleneck analysis.
        if let Some(secs) = server_stats_secs {
            srvstats::spawn(secs);
        }

        // ---- WAL wiring (Wal mode only) ----
        //
        // Skipped entirely in `--durability memory` mode — no WAL is opened,
        // recovered, or attached, and no committers/ticker spawn. The buffered
        // append path (`write_wire` → `maybe_sync_on_ack`) acks on the
        // page-cache file write alone (see `DurabilityMode::Memory` no-op).
        //
        // Order is load-bearing for crash-correctness (spec §9):
        //   1. `WalSet::open` is NON-DESTRUCTIVE — it opens the existing on-disk
        //      `wal/<i>/*.wal` segments (so recovery can read the pre-crash bytes)
        //      while resetting the in-memory cursor to lsn 1 / offset 0. A
        //      `--wal-shards` ≠ the persisted N is rejected here → exit 2 (spec §5).
        //   2. `recovery::recover` replays every durable WAL record into the
        //      per-stream files and `fdatasync`s them — after this the per-stream
        //      files are durable up to the frontier, so the OLD WAL is REDUNDANT.
        //      (The non-sharded sidecar pass that owns stream identity already ran
        //      inside `Store::new_with_tier`, so the streams exist here.)
        //   3. `reset_after_recovery` then WIPES each shard's WAL to a fresh,
        //      zero-filled segment at lsn 1. This closes the recover-before-clobber
        //      hole: without it, the live committer/appenders (which start at lsn 1
        //      / offset 0 per step 1) would write a new — possibly shorter — record
        //      over the old segment, leaving a stale suffix of whole framed records
        //      that a SECOND crash's recovery would mis-replay. After the reset the
        //      decoder hits `fallocate` zeros right after the live tail = clean EOL.
        //   4. ONLY THEN attach the WalSet (append path sees it), spawn the
        //      per-shard committers, and start the checkpoint ticker. No append can
        //      run before this point (we have not begun serving yet), so no durable
        //      record is lost and no new append collides with un-recovered WAL data.
        // Held so the shutdown path can stop + join the dedicated committer
        // threads (Tier-2a) after draining in-flight requests. `None` in
        // `--durability memory` mode (no committers spawned).
        let mut wal_for_shutdown: Option<Arc<wal::walset::WalSet>> = None;
        if handlers::durability() == handlers::DurabilityMode::Wal {
            let open_res = match wal_segment_bytes {
                Some(sz) => {
                    wal::walset::WalSet::open_with_segment_size(&data_dir, wal_shards, workers, sz)
                }
                None => wal::walset::WalSet::open(&data_dir, wal_shards, workers),
            };
            let walset = open_res.unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(2);
            });
            if let Some(readiness) = &readiness {
                readiness.attach_wal(Arc::clone(&walset));
                readiness.recovering();
            }
            wal::recovery::recover(&store, &walset).expect("WAL recovery failed");
            // Recovery can advance/torn-tail-truncate reader-visible frontiers.
            // Publish the inventory only after that authoritative reconciliation.
            store.refresh_inventory();
            walset
                .reset_after_recovery()
                .expect("WAL reset after recovery failed");
            store
                .wal
                .set(Arc::clone(&walset))
                .unwrap_or_else(|_| panic!("WAL already attached"));
            // Arm the contention timing + spawn the dependency-free stderr
            // emitter BEFORE committers/serving start, so every acquisition from
            // the first append is timed. No-op (and no clock reads) when the flag
            // is absent.
            if let Some(secs) = wal_stats_secs {
                wal::telemetry::set_stats_enabled(true);
                wal::telemetry::spawn_stats_emitter(
                    Arc::clone(&walset),
                    std::time::Duration::from_secs(secs),
                );
            }
            walset.spawn_committers();
            // Per-shard checkpoint ticker (spec §7): periodically `fdatasync` each
            // shard's touched per-stream files and recycle its WAL below the
            // checkpoint. Non-blocking w.r.t. acks (those gate on the committer's
            // durable_lsn, never on checkpoint).
            spawn_checkpoint_ticker(Arc::clone(&walset));
            // 1 Hz per-shard `WAL_STATS` emitter (spec §11): batch-size
            // distribution + durability gauges. No-op unless built with
            // `--features telemetry`; off the hot commit/append path.
            wal::telemetry::spawn_emitter(Arc::clone(&walset));
            wal_for_shutdown = Some(walset);
        }

        // This is deliberately after Store + WAL recovery/attachment, but
        // before readiness or socket exposure. The callback holds only a Weak
        // Store, and the retained handle gives graceful shutdown a deterministic
        // worker-join boundary even after `serve` releases its Store clone.
        store
            .init_retirement_executor()
            .expect("failed to initialize retirement executor");
        let retirement_for_shutdown = Arc::clone(
            store
                .retirement_executor()
                .expect("retirement executor was just initialized"),
        );
        if handlers::durability() == handlers::DurabilityMode::Wal {
            if let Some(readiness) = &readiness {
                readiness.ready();
            }
        }

        let addr: SocketAddr = (host, port).into();
        let listener = TcpListener::bind(addr).await.expect("bind failed");
        println!(
            "durable-streams-server listening on http://{addr} (data: {})",
            data_dir.display()
        );
        tokio::select! {
            _ = engine_raw::serve(store, listener, readiness.clone()) => {}
            _ = shutdown_signal() => {
                if let Some(readiness) = &readiness {
                    // Stop advertising readiness before accepting drain work or
                    // touching the committer/lock shutdown sequence.
                    readiness.stopping();
                }
                // Stop accepting (the serve future is dropped here), let in-flight
                // requests — including their group-commit fsync — finish, then flush
                // telemetry. Bounded so a stuck request can't block shutdown forever.
                // Close reactor-served SSE subscribers first so their permits are
                // released and `drain` doesn't wait out the full grace period.
                #[cfg(target_os = "linux")]
                sse_reactor::shutdown();
                engine_raw::drain(std::time::Duration::from_secs(25)).await;
                retirement_for_shutdown.shutdown().await;
                // Stop + join the dedicated committer threads (Tier-2a) AFTER the
                // request drain, so any commit a just-drained request staged is
                // covered by each committer's final drain before the thread exits.
                if let Some(walset) = wal_for_shutdown.take() {
                    walset.stop_committers();
                }
                telemetry_guard.shutdown();
            }
        }
    });
}

/// How often the checkpoint ticker POLLS its triggers. The actual checkpoint
/// cadence is per-shard and knob-driven (see `wal::shard::checkpoint_interval_ms`
/// / `checkpoint_wal_bytes`); this is just the trigger-evaluation resolution.
/// 250 ms keeps the size trigger responsive (a shard writing 1 GB/s overshoots a
/// 1 GiB budget by ≤ 250 MB) at negligible poll cost (two atomic loads/shard).
const CHECKPOINT_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Spawn the per-shard checkpoint driver (spec §7). Each poll tick, a shard is
/// checkpointed iff (a) its retained WAL exceeds `--wal-checkpoint-wal-bytes`
/// (size trigger, 0 = off), or (b) `--wal-checkpoint-interval-ms` has elapsed
/// since ITS last checkpoint (time trigger, default 3000 = the historical 3 s
/// cadence). Due shards checkpoint CONCURRENTLY (each is one spawn_blocking:
/// capture + fsync/syncfs of touched stream files → persist tails/checkpoint_lsn
/// → recycle); a serial walk would queue every shard's fsync behind one
/// device's. Because each shard's clock restarts when IT finishes, shards drift
/// apart naturally instead of storming in a synchronized wave — and with the
/// size trigger they self-schedule by their own write rates. A checkpoint error
/// is logged, not fatal — a failed/lagging checkpoint only delays WAL recycling
/// (the disk-bounded safety valve, spec §7), never blocks appends. A shard that
/// is still checkpointing is never re-fired (the in-flight set guards it), so a
/// checkpoint that takes longer than the interval degrades to back-to-back
/// checkpoints for that shard only.
fn spawn_checkpoint_ticker(walset: Arc<wal::walset::WalSet>) {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_millis(wal::shard::checkpoint_interval_ms());
        let wal_bytes = wal::shard::checkpoint_wal_bytes();
        let n = walset.shards().len();
        let mut last_done: Vec<std::time::Instant> = vec![std::time::Instant::now(); n];
        let mut in_flight: Vec<bool> = vec![false; n];
        let mut wave: tokio::task::JoinSet<usize> = tokio::task::JoinSet::new();
        // task-id → shard index, so a PANICKED checkpoint task (JoinError carries
        // no payload) still clears its shard's in-flight guard — otherwise one
        // panic would silence that shard's checkpoints forever (unbounded WAL).
        let mut task_shard: std::collections::HashMap<tokio::task::Id, usize> =
            std::collections::HashMap::new();
        let mut ticker = tokio::time::interval(CHECKPOINT_POLL.min(interval));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick — there is nothing to checkpoint at boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            // Reap finished checkpoints (non-blocking) and restart their clocks.
            while let Some(done) = wave.try_join_next() {
                let i = match &done {
                    Ok(i) => Some(*i),
                    Err(e) => {
                        eprintln!("WAL checkpoint task failed: {e}");
                        task_shard.get(&e.id()).copied()
                    }
                };
                if let Some(i) = i {
                    task_shard.retain(|_, v| *v != i);
                    in_flight[i] = false;
                    last_done[i] = std::time::Instant::now();
                }
            }
            for (i, shard) in walset.shards().iter().enumerate() {
                if in_flight[i] {
                    continue;
                }
                let size_due = wal_bytes > 0 && shard.wal_size_bytes() >= wal_bytes;
                let time_due = last_done[i].elapsed() >= interval;
                if !(size_due || time_due) {
                    continue;
                }
                in_flight[i] = true;
                let shard = Arc::clone(shard);
                let handle = wave.spawn(async move {
                    if let Err(e) = shard.checkpoint().await {
                        eprintln!("WAL checkpoint failed for shard {:?}: {e}", shard.dir());
                    }
                    i
                });
                task_shard.insert(handle.id(), i);
            }
        }
    });
}

/// How often the meta sweeper flushes dirty sidecars (#4691). The sidecar's
/// producer/access state is a non-durable, lagging flush by contract; 1 s keeps
/// the lag tighter than the wal checkpoint's 3 s cadence while still batching
/// away the per-stream timer + per-append rewrite the 100 ms debounce cost.
const META_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Spawn the store-level meta-sidecar sweeper: each tick drains the
/// `mark_meta_dirty` queue and writes every still-dirty stream's sidecar in one
/// `spawn_blocking` task (vs one timer task + one blocking task PER STREAM per
/// 100 ms under the old debounce — the ~5x memory-mode CPU overhead of #4691).
fn spawn_meta_sweeper(store: Arc<Store>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(META_SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick — nothing can be dirty at boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if store.meta_sweep.lock().unwrap().is_empty() {
                continue;
            }
            let s = Arc::clone(&store);
            let _ = tokio::task::spawn_blocking(move || s.sweep_meta_once()).await;
        }
    });
}

/// Resolve on SIGINT (Ctrl-C) or SIGTERM (systemd/Kubernetes stop). On non-Unix,
/// only Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
