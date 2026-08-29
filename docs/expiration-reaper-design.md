# Periodic stream expiration reaper

Status: proposed, revised after Claude Opus 5 review

## Summary

Durable Streams currently evaluates `Stream-TTL` and `Stream-Expires-At` only
when a request looks up that stream. An expired stream that is never requested
again therefore remains in the registry and on disk indefinitely.

Add a bounded background scan over only streams that have an expiration policy.
The scan decides which streams are candidates; a shared retirement coordinator
does the destructive work for proactive expiry, lazy request-time expiry, and
explicit `DELETE`.

The retirement coordinator is the load-bearing part of this design. It must:

- fence new appends;
- account for appends that already left the appender mutex but are still waiting
  for WAL durability and acknowledgment;
- prevent deferred checkpoint/meta workers from recreating sidecars;
- update subscriptions, inventory, fork references, and WAL bookkeeping;
- bound all filesystem, remote-GC, and fork-cascade work; and
- prevent delayed cleanup of an old stream from affecting a replacement at the
  same path.

The WAL is not an archive. It retains crash-recovery records until checkpointed
stream files are durable, then recycles obsolete WAL segments. Expiry removes
the per-stream data and metadata; it does not archive WAL history.

## Problem

There are two separate problems:

1. **Discovery:** `Store::get` is the only production caller of
   `StreamState::is_expired`. Cold abandoned streams are never discovered.
2. **Safe retirement:** the current delete helper is safe enough for a rare,
   awaited explicit `DELETE`, but it is not a complete high-volume retirement
   protocol. Appends release the appender lock before their WAL wait,
   visibility publication, sidecar writes, subscription notification, and 2xx
   response. Checkpoint and meta-sweep queues also retain `Arc<StreamState>` and
   can write after unlink.

A timer that iterates `Store::streams` and invokes the current delete helper is
incorrect. The safe retirement protocol must land before proactive reaping.

## Goals

- Reclaim expired streams without another request for their exact path.
- Keep request-time expiry enforcement in every operating mode.
- Preserve sliding TTL: successful reads, compatible `PUT`, and successful
  writes move the deadline.
- Preserve absolute expiry: access never extends `Stream-Expires-At`.
- Never unlink a stream while an append can still publish or acknowledge 2xx.
- Never acknowledge 2xx after retirement has won the fence.
- Allow a path to be recreated only after path-scoped logical deletion effects
  for the old stream have completed.
- Preserve fork semantics and collect soft-deleted zero-reference parents.
- Keep scan work, delete rate, filesystem work, blocking-pool use, remote
  requests, and retry memory bounded.
- Keep WAL recovery and checkpoint invariants intact while preventing WAL
  metadata from growing with all stream IDs ever created.
- Make backlog, lag, clock anomalies, failures, and reclaimed bytes observable.

## Non-goals

- WAL archival or point-in-time recovery.
- Retention policies based on stream size, event time, namespace, or account.
- Sub-second physical deletion. The HTTP lookup path is the observable expiry
  boundary; background reclamation may lag by a bounded scan period.
- Enabling tiered proactive deletion until persistent remote-GC tombstones exist.
- Making proactive expiry more crash-durable than it needs to be. There is no
  client acknowledgment for reaper cleanup, so a crash may undo an unlink and
  the recovered expired stream may be reaped again.

## Existing expiry contract

- `Stream-TTL` and `Stream-Expires-At` are mutually exclusive and immutable for
  the lifetime of a stream.
- Every GET, catch-up or live, refreshes TTL once at request dispatch. An open or idle SSE response, including batches on that response, does not refresh again.
- Successful body appends and close-only writes refresh `last_access`.
- Compatible `PUT` refreshes TTL.
- `HEAD` does not refresh TTL.
- A stream without TTL or absolute expiry is never scanned.
- If forks reference a deleted source, its data remains behind a soft-delete
  tombstone until the final child releases the reference.
- `last_access` persistence is deliberately lagging and second-granular. After
  recovery, a TTL deadline may be conservatively early by the metadata flush or
  checkpoint lag plus sub-second truncation.

The design changes how expiration is discovered and retired, not these rules.

## Decisions

### Use a bounded round-robin index, not a deadline heap

Maintain a registry containing exactly the live streams with TTL or absolute
expiry:

```rust
struct ExpiringStreams {
    by_id: BTreeMap<u64, Weak<StreamState>>,
}
```

The reaper owns a monotonically advancing stream-ID cursor. Each scan takes a
bounded page after the cursor, wraps at the end, clones weak references, releases
the index lock, and evaluates deadlines under each stream's shared read lock.

Properties:

- At most one entry exists per live expiring stream because the key is the
  immutable stream ID.
- Hot reads/appends do not touch a global timer structure.
- There are no stale deadline entries on every TTL refresh.
- A restart does not enqueue every expired stream for simultaneous execution;
  the scan rate bounds discovery by construction.
- Deleted entries do not retain `StreamState` because the index holds `Weak`.
- A stale candidate validates `stream_id` and `Arc` identity before fencing.

Register only after a create and its initial sidecar succeed, and once for each
recovered expiring stream before serving. Remove on hard or soft retirement.
The index exists in off, observe, and delete modes. Recovered `soft_deleted && ref_count == 0` streams enter retirement coordination in every mode.

The index lock is never held across `.await`, a `DashMap` operation, or cleanup.

### One canonical deadline function

Use one implementation for request lookup, observe mode, and delete mode:

```rust
fn expiry_deadline(&self) -> Option<SystemTime>;
fn is_expired_at(&self, now: SystemTime) -> bool;
```

Requirements:

- Preserve the protocol's strict boundary consistently; no component may use a
  different `>`/`>=` test.
- Use `checked_add` for `last_access + ttl`; a client-provided `u64::MAX` TTL
  must not panic a request or reaper task. Overflow means effectively no finite
  TTL deadline.
- Handle times before `UNIX_EPOCH` without panic.
- Tests at exactly the deadline prove there is no early deletion or scan spin.

### Separate candidate discovery from retirement

The scanner only reads state and queues a candidate. It never takes the
appender lock and never unlinks a file.

Candidates enter a deduplicated, bounded retirement queue keyed by stream ID.
Queue entries hold a strong `Arc` because retirement may remove the stream from
the public registry before physical cleanup completes. Each `StreamState` has a
`retirement_queued` flag so proactive scan, lazy expiry, and retries cannot add
duplicates.

If the queue is full:

- request-time expiry still rejects the stream;
- the candidate remains discoverable on the next scan or request;
- a critical backlog metric/log fires; and
- no unbounded fallback task is spawned.

## Safe retirement protocol

### Stream-local state

Add transient, non-persisted coordination to `StreamState`:

```rust
fenced: AtomicBool,
inflight_appends: AtomicUsize,
inflight_appends_zero: Notify,
retirement_queued: AtomicBool,
deleted: tokio::sync::watch::Sender<bool>, // starts false; retirement sends true
```

Keep the existing persisted `soft_deleted` field authoritative. Do not add a
persisted lifecycle enum or delete reason. Old and new binaries therefore keep
the same sidecar compatibility and rollback behavior.

### Handler-owned request resolution and append guard

Store::get remains synchronous. Handlers own any awaits needed for request-visible expiry resolution. Readers subscribe to the level-triggered watch<bool> deletion signal and then recheck state, eliminating notification-registration races. The live fast path confirms under shared state that the stream is live; a TTL GET touches there once. For a due candidate, the handler takes the appender lock, rechecks identity and deadline, fences before returning 404, then admits retirement. A losing TTL touch or append can renew only before this appender-locked fence.

Store::create returns CreateResult::Retiring for a due or fenced occupied entry and never config-matches it. The PUT handler resolves that entry first, then awaits logical retirement for at most --expiry-logical-retirement-timeout-ms 5000; only its completed path retries create once. Timeout, active retirement, or failed admission returns 503 Service Unavailable with Retry-After: 1 to PUT and DELETE. DELETE that itself discovers a due stream follows existing 404 behavior after fencing/admission; only a DELETE racing an already-active retirement returns 503.

The append guard still covers WAL wait, publication, sidecar work, subscription append notification, and response decision. It rechecks the fence after WAL wait before visibility or 2xx and decrements on every exit. A post-WAL fence win may leave bytes durable in WAL but never acknowledges false success.

### Retirement linearization

For a due candidate, validate registry path, stream ID, and Arc identity; cheaply recheck the deadline; acquire the appender lock and fence only if still due; then wait for in-flight guards to drain using registration-before-check. Set the watch<bool> deletion signal true; readers subscribe and recheck.

Before path reuse, await and confirm the in-memory SubscriptionManager deletion transition. That transition must not re-enter Store::get or append, is not persistent, and returns delivery intent. Submit intents to a dedicated bounded delivery lane, never a detached spawn: --expiry-delivery-queue-capacity 256 and --expiry-delivery-concurrency 32. Queue full drops delivery and records metric/log; it never retains the fence.

Retire registry and index entries after that transition. Inventory publication and removal are both identity-safe: each validates expected stream_id after asynchronous delay. Forget deferred metadata and WAL state, then enqueue physical cleanup. A PUT that owns expiry awaits logical retirement and retries create once. A racing PUT or DELETE returns 503 with Retry-After: 1. Any due 404/503 response attempts admission when retirement_queued is false; this is the off-mode recovery path after saturation.

### Request-time behavior in every mode

Handlers own due-resolution awaits around synchronous Store::get. Off disables only proactive scanning; lazy request-time and explicit retirement coordination always run.

- Every catch-up or live GET touches once at request dispatch; idle SSE and batches on that response do not touch again.
- HEAD confirms live/not-expired without touch.
- Append and close use the appender-locked guard; successful writers touch TTL.
- A due candidate is fenced before GET, HEAD, or append returns 404; persisted soft deletion returns 410.
- Compatible PUT config-matches only live, unfenced state. Its owning expiry path retires then retries create once.
- Active or saturated retirement yields PUT/DELETE 503 with Retry-After: 1. While cleanup_failed, GET/HEAD/append remain 404 and PUT/DELETE return 503 with Retry-After: 60.

### Fork cleanup

Fork-source resolution is a Store::get caller and uses the handler-owned due path: recheck/fence/admit, then return the existing 404 fork source not found. It cannot increment ref_count or create a fork from a due or fenced source. Subscription wake lookup is another Store::get caller: it treats due/fenced as absent, does not admit retirement, and does not re-enter the coordinator.

Use the same bounded retirement queue for parent cascades:

- `ref_count > 0`: persist `soft_deleted`, remove from the expiration index,
  keep the registry tombstone and bytes, and notify subscriptions.
- When `release_parent` reaches zero, enqueue hard cleanup instead of spawning
  an unbounded detached blocking task.
- On recovery, enqueue `soft_deleted && ref_count == 0` through mode-independent retirement coordination.
- Hard cleanup removes the exact inventory entry as well as data/meta/segments.

### Deferred metadata writers

Fencing sets meta_dirty false. Meta sweep and checkpoint flush skip fenced streams, and close/appends check the post-WAL fence before write_meta_sync. Retirement holds meta_lock across fenced unlink, so an already-started writer cannot rename a sidecar back. Nonterminal fork-parent write_meta_sync also uses bounded physical work.

### WAL bookkeeping

WalSet::forget_stream is cold maintenance only. Under the tails-cache maintenance lock it first seeds lazy tails-cache state from disk, then removes the resident ID and adds a per-shard forgotten HashSet tombstone; unseeded cache state therefore cannot preserve the stream. It does not scan or remove existing Arc values from the dirty Vec, and per-append register_dirty and checkpoint-failure re-registration do not consult the forgotten set or take a shard maintenance lock. Existing dirty Arcs live until the next checkpoint; fenced sidecar flush skips them.

persist_durable_tails is the sole forgotten-set filter. On the next successful persistence it filters both normally drained and failure-re-registered Arc IDs, writes the pruned map, fsyncs it, renames it, and fsyncs the parent directory. Only after that successful durable sequence does it reacquire the maintenance lock and clear those tombstones. At boot, prune an unknown tail ID only when it has neither recovered StreamState nor surviving or quarantined data file. Otherwise retain torn-tail proof for a reparable sidecar. WAL segments remain under ordinary checkpoint/recovery management.

### Physical cleanup modes and capacity

ExplicitDelete waits only for its first prioritized physical-cleanup attempt, including directory sync. Return 204 only after that durable attempt succeeds. If it fails, return 503 Service Unavailable with Retry-After: 1 and let the coordinator continue bounded retries in the background; never hold the HTTP request across all 10 retries. Expiry returns I/O errors without parent sync; a crash may resurrect bytes, but expiry still rejects them.

The bounded coordinator queue feeds a dedicated four-worker physical executor, separate from checkpoint and Tokio blocking work. Defaults are expiry-retirement-queue-capacity 4096, expiry-retirement-concurrency 64, expiry-physical-queue-capacity 1024, and expiry-cleanup-workers 4. Coordination is async and never occupies physical threads. Split physical slots into 960 proactive and 64 interactive-reserved slots; interactive has priority and one of four workers reserved. Reserve eight coordinator permits for interactive callers; proactive work uses at most 56 permits and three workers.

Admission/cleanup retries at most 10 times with exponential backoff capped at 60 seconds. Then record cleanup_failed, release queue memory, and retain the fence. Scanner, lazy, and explicit paths may re-admit after five-minute cooldown. Emit oldest-fence age and cleanup_failed telemetry and test permanent EACCES.

The no-unbounded-spawn rule applies to proactive and tier-off cleanup. Existing tiered explicit/lazy remote-GC behavior remains until persistent remote-GC tombstones exist.

### Tiered streams

Delete mode is rejected at startup whenever tier != off, including S3, local tier, and blobs, until persistent remote-GC tombstones and bounded remote cleanup exist. Off, observe, lazy expiry, and explicit delete retain their current tiered behavior.

## Scanner and operating modes

Run one supervised scanner after recovery and WAL initialization. The expiring index and retirement coordinator start in every mode; off disables only proactive scan.

Initial controls:

    --expiry-reaper-mode off|observe|delete       default off
    --expiry-scan-rate 10000
    --expiry-delete-rate 100
    --expiry-retirement-queue-capacity 4096
    --expiry-retirement-concurrency 64
    --expiry-physical-queue-capacity 1024
    --expiry-cleanup-workers 4
    --expiry-delivery-queue-capacity 256
    --expiry-delivery-concurrency 32
    --expiry-logical-retirement-timeout-ms 5000
    --expiry-startup-grace-seconds 60
    --expiry-bulk-fraction 0.25
    --expiry-clock-jump-seconds 300

Indexed infrastructure always passes expiry-reaper-mode explicitly. Observe scans with shared reads only. Delete enqueues bounded proactive retirement and is rejected whenever tier != off until remote-GC tombstones exist.

### Startup and clock safety

- During startup grace, build and observe the index but do not proactively
  delete. Lazy lookup still enforces expiry.
- Complete one observe pass before enabling deletion.
- If the due fraction exceeds `expiry_bulk_fraction`, pause proactive deletion,
  emit a critical metric/log, and require an explicit operator override. This
  catches stale metadata, an unexpectedly long outage, or a clock event before
  mass deletion.
- Compare wall-clock elapsed time with monotonic elapsed time across sleeps. A
  forward/backward divergence over the configured threshold pauses proactive
  deletion. Lazy checks continue to follow the public wall-clock contract.
- The scanner is supervised. Panic/restart counters and last-success time are
  externally visible; safe arithmetic should make clock input non-panicking.

## Observability

Add bounded-cardinality metrics without paths as labels:

- `ds.expiry.index.entries`
- `ds.expiry.scan.checked`
- `ds.expiry.scan.duration`
- `ds.expiry.due`
- `ds.expiry.outcome{outcome=renewed|observe|fenced|soft_deleted|reaped|stale|failed}`
- `ds.expiry.lag`
- `ds.expiry.cleanup.duration`
- `ds.expiry.reclaimed.local_bytes`
- `ds.expiry.queue.depth`
- `ds.expiry.queue.retries`
- `ds.expiry.clock_drift`
- `ds.expiry.bulk_guard.paused`
- `ds.expiry.fence.oldest_age`
- `ds.expiry.cleanup_failed`
- `ds.expiry.delivery.dropped`
- `ds.expiry.delivery.queue.depth`

Log failures with stream ID and a hashed path, never the raw path as a metric
label. Rate-limit repeated mount/object-store errors.

Expose mode, scan cursor progress, last completed pass, due fraction, oldest due
age, queue depth/capacity, active cleanup workers, retry count, oldest fence age, cleanup-failed count, delivery queue depth/drops, and last successful
cleanup through server stats/admin observability.

Inventory pagination may receive repeated generation changes during a large
reap and return its existing 409-restart response. Document this operationally;
a snapshot inventory protocol is separate work.

## Failure behavior

| Failure | Required behavior |
| --- | --- |
| Due request | Handler fences under appender lock before 404; Store::create cannot config-match due/fenced resident state. DELETE discovering due returns existing 404; only racing DELETE is 503. |
| Active or saturated retirement | PUT and DELETE return 503 with Retry-After: 1. |
| Terminal cleanup failure | Keep fence, release queue memory, record cleanup_failed; GET/HEAD/append are 404 and PUT/DELETE are 503 with Retry-After: 60 until cooldown. |
| Subscription delivery failure or full delivery lane | Confirmed in-memory transition already gates reuse; drop delivery and record metric/log only. |
| Metadata race | meta_lock spans fenced unlink, preventing sidecar rename resurrection. |
| WAL race | Only successful persist filters normally drained and failure-re-registered dirty Arcs; forget never scans the dirty Vec. |
| Tiered delete mode | Startup rejects every tier != off configuration until remote-GC tombstones exist. |

## Tests

Use injected time and deterministic barriers. Test deadline arithmetic, every catch-up/live GET dispatch touch, SSE idle/batch no-touch, writer touch, and handler-owned fencing around synchronous Store::get. Test CreateResult::Retiring for due/fenced occupied entries, the 5000 ms owning-PUT logical timeout, DELETE discovering due at existing 404 versus racing DELETE at 503 Retry-After 1, saturated PUT at 503 Retry-After 1, and cleanup_failed at 503 Retry-After 60 with cooldown and permanent EACCES.

Test all Store::get callers: fork-source due/fenced resolution returns 404 fork source not found without ref_count increment or fork creation; subscription wake lookup treats due/fenced as absent and neither admits retirement nor re-enters coordinator. Test the level-triggered watch<bool> signal by subscribing then rechecking.

Test that in-process subscription transition returns delivery intent and gates reuse without Store re-entry or persistence/restart claims. Bound delivery lane at 256/32; a full lane drops delivery, records metrics, and never retains fence. Include delivery lane capacity in expiry-storm bounds. Test identity-safe inventory publication/removal, meta_lock races, bounded fork metadata, and cold forgotten-set maintenance: seed lazy cache from disk before forget, no O(n) dirty scan or per-append lock, only successful pruned write plus fsync, rename, and parent-directory fsync clears tombstones after filtering drained and failure-re-registered Arcs, and boot pruning is conservative.

Test crash states after fence, after registry removal, and after non-durable expiry unlink without directory sync. Test all-mode index and mode-independent soft-deleted zero-reference recovery; 4096/64 coordinator, 1024 physical slots split 960 proactive/64 interactive with 8/56 and one-worker/three-worker reservations; every tier != off guard; and telemetry. Test explicit DELETE first prioritized attempt semantics.

## Rollout

1. Land canonical deadline arithmetic and the full-path append/retirement fence
   with proactive scanning off. Run explicit DELETE conformance and crash tests.
2. Land identity-safe inventory removal, subscription deletion results/wakeup,
   meta/checkpoint suppression, WAL `forget_stream`, fork cleanup, and recovery
   pruning.
3. Land the expiring-stream index and `observe` mode. Compare candidates with
   sidecar deadlines in dev; lazy expiry continues to reclaim.
4. Enable `delete` in dev with short-lived probe streams. Verify files,
   sidecars, tails maps, fork retention, and mode-independent soft_deleted refcount-zero recovery; explicitly do not verify subscription persistence.
5. Run high-cardinality scan and expiry-storm load tests.
6. Deploy production in `observe`, validate due fraction and clock/bulk guards,
   then explicitly change infrastructure to `delete`.
7. Keep `off` as rollback; it disables proactive scanning only, never lazy
   correctness or cleanup.

## Implementation slices

1. Expiry math, all synchronous Store::get caller policies, handler-owned resolution, CreateResult::Retiring, and logical timeout.
2. Full-ack append guard and level-triggered watch<bool> deletion signal.
3. Identity-safe registry/inventory and in-memory subscription transition plus bounded delivery lane.
4. Meta-lock unlink, cold WAL cache seeding/tombstone durability, bounded fork metadata, and conservative recovery pruning.
5. Bounded coordinator/physical queues, slot reservations, retry/cooldown, cleanup_failed, and tier guard.
6. All-mode index, scanner safety valves, delivery telemetry, and observability.
7. Deterministic race, fork, SSE, capacity/delivery-storm, EACCES, and crash-after-fence/registry-removal/non-durable-unlink qualification.
8. Explicit infrastructure flags and runbook.

## Claude Opus 5 review disposition

The first review rejected the deadline heap and appender-lock-only fence. Accepted findings remain the full-ack fence, identity-safe inventory, sidecar race protection, fork cleanup, lazy correctness, WAL maintenance, and bounded work.

The second review corrected this design's request/PUT handling, in-memory subscription reality, WAL coordination, capacity/priority/retry contract, tier guard, and SSE TTL semantics. The final review additionally pins cold WAL tombstone maintenance, all Store::get caller behavior, and bounded delivery. This document incorporates those corrections in the sections above; it does not require durable subscription records or a lock held across checkpoint.
