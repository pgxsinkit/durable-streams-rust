# Periodic stream expiration reaper

Status: implemented with TDD; pending final multi-model review

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
- Enabling S3 tiering in the current deployment.
- Making proactive expiry more crash-durable than it needs to be. There is no
  client acknowledgment for reaper cleanup, so a crash may undo an unlink and
  the recovered expired stream may be reaped again.

## Existing expiry contract

- `Stream-TTL` and `Stream-Expires-At` are mutually exclusive and immutable for
  the lifetime of a stream.
- Catch-up and live `GET` requests refresh `last_access` for TTL streams.
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

Serialize same-path creation with a bounded path-striped mutex, without holding a
registry shard across I/O. Keep the new state unpublished until the complete
initial sidecar transaction succeeds, then hold its metadata barrier across the
short registry, inventory, and expiration-index publication. Physical retirement
cannot pass that barrier between projections, and concurrent readers/appends
cannot observe a child that can still be rolled back. Register each recovered
expiring stream before serving. Remove on hard or soft retirement.
Page through recovered `soft_deleted && ref_count == 0` streams and enqueue them
for hard cleanup through the normal bounded coordinator in every mode; never
perform a synchronous, unbounded startup sweep. They are invisible to the
normal lookup path.

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
deleted: CancellationToken, // or equivalent wake primitive
```

Keep the existing persisted `soft_deleted` field authoritative. Do not add a
persisted lifecycle enum or delete reason. Old and new binaries therefore keep
the same sidecar compatibility and rollback behavior.

### Append guard covers the full acknowledgment path

The existing appender mutex does **not** cover the full append lifecycle: it is
released before `wait_durable_lsn`, `publish_durable_tail`, close metadata, and
the response. Add an RAII append guard:

1. Acquire the per-stream appender lock.
2. Check `fenced`, `soft_deleted`, and expiration under shared state.
3. If live, increment `inflight_appends` while still holding the appender lock.
4. Perform write, WAL stage, WAL durability wait, visibility publication,
   close metadata, subscription append notification, and response decision.
5. Check `fenced` again after the WAL wait and before visibility or 2xx. If an
   absolute expiry fenced the stream while this append was waiting, do not
   publish, do not recreate metadata, and return the pinned missing/gone error.
6. Decrement through the guard on every return/panic path and notify when zero.

The bytes may already be durable in WAL when the post-wait fence check fails.
That is acceptable: retirement discards the stream, and the client is never
given a false successful acknowledgment.

### Retirement linearization

For a due candidate:

1. Validate the current registry maps the path to the same stream ID and `Arc`.
2. Do a cheap shared-lock deadline check. Renewed TTL streams stop here without
   touching the appender lock.
3. Acquire the appender lock; revalidate identity, fence state, and deadline.
4. If still expired, set `fenced = true` under the appender lock. No later
   append can start an append guard.
5. Release the appender lock and wait for `inflight_appends == 0`, using
   registration-before-check so a zero transition cannot be missed.
6. Trigger the stream deletion cancellation primitive as soon as the fence is
   published, before paced physical cleanup. Long-polls return the pinned
   deletion response; SSE closes so reconnect observes deletion. Explicit
   `DELETE` uses the same wake path.
7. Apply the subscription deletion transition and persist it before the path is
   reusable. `SubscriptionManager::on_stream_deleted` must report failure rather
   than only log it; failure keeps the old path fenced and queues bounded retry.
8. Perform exactly one stream's fork-aware physical unlink on the bounded
   blocking executor and account the local bytes actually removed.
9. Forget that stream from WAL bookkeeping under checkpoint maintenance
   exclusion.
10. Remove the exact registry, inventory, and expiration-index entries. A
    returned zero-reference parent becomes a paced continuation only after this
    job acquires its exact marker. If active/quarantined work already owns that
    marker, transfer the parent and terminally release the completed child job;
    never poll the conflicting marker while retaining admission or shutdown.

The path remains briefly occupied and fenced through step 7 so a delayed
path-only subscription notification cannot mutate a newly recreated stream's
subscription lifetime. A `PUT` that itself discovers expiration awaits this
retirement and retries creation once, preserving the current create-after-expiry
behavior. If a lazy read already admitted that exact stream ID and `Arc`, the PUT
joins the coordinator's sticky result instead of admitting duplicate work. The
join is bounded at five seconds; a timeout remains retryable. An unrelated PUT
racing an already-fenced, non-expired explicit retirement receives the pinned
cleanup-in-progress response below.

No registry or inventory operation is path-only after asynchronous delay.
`InventoryEntry` gains an internal `stream_id`, and removal uses
`remove_inventory(path, expected_stream_id)`.

### Request-time behavior in every mode

Lazy expiry remains the correctness safety net:

- TTL `GET`: atomically confirm live/not-expired and refresh `last_access` under
  one shared write lock.
- `HEAD`: atomically confirm live/not-expired without refreshing access.
- Append/close: perform the live/expiry check under the appender lock before the
  full-path append guard begins.
- Compatible `PUT`: atomically touch when live; when expired, await retirement
  and retry create once.

If a request loses to expiration it cannot refresh or mutate the stream. It
returns:

- hard-expired/fenced stream: `404 stream not found`;
- persisted soft-deleted stream: `410 stream is deleted`.

An expired fork parent that still has children becomes the existing
soft-deleted state and therefore returns 410 after retirement. Child reads do
not refresh the parent's TTL: TTL controls the source's direct lifetime, while
fork references control physical byte retention.

### Fork cleanup

Use the same bounded retirement queue for parent cascades:

- `ref_count > 0`: persist `soft_deleted`, remove from the expiration index,
  keep the registry tombstone and bytes, and notify subscriptions.
- When `release_parent` reaches zero, enqueue hard cleanup as another paced
  attempt instead of spawning an unbounded detached blocking task. Keep the
  original admission permit and request completion across the continuation;
  report completion only when the whole chain finishes.
- On recovery, page and enqueue `soft_deleted && ref_count == 0` through the
  same admission/rate controls in every mode.
- Hard cleanup removes the exact inventory entry as well as data/meta/segments.

### Deferred metadata writers

Fencing must prevent `.meta` resurrection:

- set `meta_dirty = false` at retirement;
- `sweep_meta_once` skips fenced streams and drops their queued `Arc`;
- checkpoint sidecar flush skips fenced streams; and
- close/appends perform their post-WAL fence check before `write_meta_sync`.

The queues may retain an `Arc` until their next bounded drain, but they cannot
write a new sidecar after fencing.

### WAL bookkeeping

No expiration tombstone is added to the WAL record format. Add a
`WalSet::forget_stream(stream_id)` maintenance operation that coordinates with
the shard checkpoint:

- remove the stream from the shard dirty set;
- remove its ID from the resident cumulative durable-tail map;
- prevent an in-progress checkpoint from re-adding the ID after forget;
- persist the pruned map on the next checkpoint; and
- prune tail-map IDs with no recovered stream during boot.

This needs a per-shard maintenance/checkpoint exclusion point. Without it, a
checkpoint can drain the old `Arc`, race retirement, and reinsert the deleted ID
into `tails_cache`. The map otherwise grows monotonically with every expired
stream and its O(total IDs) rewrite runs every checkpoint forever.

The reaper never edits WAL segments. Normal checkpoint/recovery retains or
recycles records according to the existing durability frontier.

### Physical cleanup modes

Refactor cleanup into one synchronous blocking-pool entry point with explicit
durability:

- `ExplicitDelete`: unlink/soft tombstone and parent-directory sync before 204.
- `Expiry`: return I/O errors but do not sync the parent directory. A crash may
  undo the unlink; the recovered deadline is still expired and lazy lookup will
  not serve it.

Do not use the existing detached, no-result deletion helper. Retirement needs an
`io::Result` for bounded retry.

Local reclaimed bytes means the live data-file length plus locally staged
segment lengths actually unlinked, not logical tail minus base offset and not
remote object bytes.

### Tiered streams

`gc_remote_segments` currently spawns an unbounded detached task and remote
cleanup is best effort. Proactive delete mode must not be combined with S3
tiering until remote deletion has a persistent GC tombstone and uses the same
bounded work queue/semaphore. Until then, startup rejects or loudly disables
proactive `delete` when `tier != off`; `observe`, lazy expiry, and explicit
delete retain their documented current behavior.

## Scanner and operating modes

Run one supervised scanner after recovery and WAL initialization.

Implemented controls:

```text
--expiry-reaper-mode off|observe|delete
--expiry-scan-rate 10000
--expiry-delete-rate 100
--expiry-delete-concurrency 4
--expiry-startup-grace-seconds 60
--expiry-bulk-fraction 0.25
--expiry-clock-jump-seconds 300
```

Scan rate is capped at 1,000,000/s, delete admission at 100,000/s, and cleanup
concurrency at 1,024 so hostile or mistaken flags cannot overflow the bounded
channel/semaphore. Infrastructure always passes the mode explicitly.

- `off`: no proactive expiration scan. Lazy request-time expiry and pageable
  recovery cleanup still retire through the bounded coordinator.
- `observe`: scan with shared reads only; emit would-expire/backlog metrics. Do
  not acquire appender locks or enqueue proactive cleanup. Lazy expiry still
  retires and reclaims.
- `delete`: scan and enqueue bounded proactive retirement.

The scan rate bounds registry inspection. Delete rate and concurrency separately
bound destructive/transitive work. The queue/semaphore also owns fork cascades
and remote GC; no helper may escape with an unbounded `tokio::spawn` or
`spawn_blocking`.

### Startup and clock safety

- During startup grace, build and observe the index but do not proactively
  delete. Lazy lookup still enforces expiry.
- Complete one observe pass before enabling deletion.
- Once a pass contains at least 64 due streams, if its due fraction exceeds
  `expiry_bulk_fraction`, pause proactive deletion, emit a critical metric/log,
  and require an explicit operator override. The absolute floor prevents a
  small ordinary population such as 3 of 8 streams from permanently pausing a
  process, while still catching stale metadata, a long outage, or a clock event
  before mass deletion.
- Compare wall-clock elapsed time with monotonic elapsed time across sleeps. A
  forward/backward divergence over the configured threshold pauses proactive
  deletion. Lazy checks continue to follow the public wall-clock contract.
- The scanner is supervised. Its monotonic startup baseline and sticky
  bulk/clock latches live above a generation, so a panic/restart cannot reset a
  safety decision. Restart counters and last-success time are externally
  visible; safe arithmetic should make clock input non-panicking.

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

Log failures with stream ID and a hashed path, never the raw path as a metric
label. Rate-limit repeated mount/object-store errors.

Expose mode, scan cursor progress, last completed pass, due fraction, oldest due
age, queue depth/capacity, active cleanup workers, retry and quarantine counts,
and last successful cleanup through server stats/admin observability.

Inventory pagination may receive repeated generation changes during a large
reap and return its existing 409-restart response. Document this operationally;
a snapshot inventory protocol is separate work.

## Failure behavior

| Failure | Required behavior |
| --- | --- |
| TTL renewed before fence | Cheap recheck sees the later deadline; no appender lock or cleanup. |
| Append already staged before fence | Guard remains in flight; post-WAL fence check prevents publish/2xx; retirement waits before unlink. |
| Same path recreated | Old cleanup uses file ID, `Arc` identity, inventory stream ID, and completed path-scoped subscription transition; it cannot affect the replacement. |
| Queue full | No unbounded task. Lazy access rejects expiry; scanner retries later; critical backlog metric fires. |
| Local cleanup fails | Stream stays fenced through six bounded attempts with backoff. Exhaustion quarantines the exact incarnation until restart, releases admission for unrelated work, and never restores live after partial unlink. |
| Corrupt sidecar owns WAL proof | Preflight before replay/reset refuses WAL startup and leaves retained append/checkpoint-tail evidence intact for operator repair. An unmappable quarantine fails closed. |
| Crash during expiry unlink | Stream may recover, is still expired, and is rejected/requeued. |
| Fork parent expires | Persist soft deletion; children retain bytes; final release enters bounded hard cleanup. |
| Meta/checkpoint queue races | Fenced checks suppress sidecar writes; WAL maintenance exclusion prevents tail-map resurrection. |
| Clock jumps | Proactive delete pauses above threshold; lazy wall-clock enforcement remains. |
| Reaper falls behind | Request path remains correct; lag/backlog alerts fire; unrelated stream I/O is not blocked. |

## Tests

Use an injected clock and deterministic barriers; correctness tests do not sleep
on wall time.

### Deadline and scan tests

- TTL, absolute expiry, exact-boundary, pre-epoch, and `u64::MAX` arithmetic.
- Only expiring streams enter the B-tree index; create/recovery/delete maintain
  exactly one entry per ID.
- Sustained touches do not mutate or grow the index.
- Cursor paging remains bounded and makes progress under concurrent create/delete.
- Off and observe modes continue to reclaim when lazy lookup discovers expiry.
- Observe mode takes no appender locks.
- Startup grace, bulk guard, delete-rate cap, and wall/monotonic drift pause.

### Retirement race tests

Use barriers around appender acquisition, `drop(ap)`, WAL durability wake,
visibility publish, fence, subscription persistence, registry removal, and
unlink:

- read touch wins: TTL stream survives;
- fence wins: read cannot refresh or serve;
- append finishes before revalidation: TTL deadline renews and survives;
- append is between `drop(ap)` and WAL wake when fenced: no 2xx, no tail
  notification, no sidecar recreation, cleanup waits for its guard;
- delayed cleanup cannot remove a replacement's inventory or subscription state;
- expired `PUT` awaits retirement and creates a fresh ID;
- explicit delete and expiry share the same fence/wakeup protocol;
- in-flight file reads finish safely after unlink;
- long-poll wakes with the pinned deletion response and SSE terminates.

### Side-channel and recovery tests

- Meta sweep and checkpoint after fence do not recreate `.meta`.
- Reaped subscriptions have no dangling leases/cursors after restart.
- `soft_deleted && ref_count == 0` is collected at recovery.
- Fork parent inventory is removed on final release.
- WAL dirty set and cumulative tails map stay bounded across repeated
  create/expire cycles.
- Checkpoint racing `forget_stream` cannot reinsert a retired ID.
- WAL and memory durability modes both cover lazy and proactive expiry.
- Crash before/after fence, subscription transition, registry removal, unlink,
  and explicit-delete directory sync.
- A non-durable expiry unlink resurrected by crash is rejected before serving
  and reaped again.

### Load tests

- One million indexed expiring streams: index memory, full-pass time, and scan
  CPU remain within budget.
- One hot stream under sustained reads/appends causes no index writes and no
  proactive appender-lock acquisitions while renewed.
- A 100k expiry storm stays within configured delete rate/concurrency and does
  not create unbounded Tokio/blocking/remote tasks.
- Unrelated-stream p99 read and append latency degrades no more than 5% during
  the storm.
- Steady-state expiry lag p99 is at most 60 seconds; a controlled storm drains
  within 10 minutes without consuming WAL checkpoint headroom.

## Rollout

1. Land canonical deadline arithmetic and the full-path append/retirement fence
   with proactive scanning off. Run explicit DELETE conformance and crash tests.
2. Land identity-safe inventory removal, subscription deletion results/wakeup,
   meta/checkpoint suppression, WAL `forget_stream`, fork cleanup, and recovery
   pruning.
3. Land the expiring-stream index and `observe` mode. Compare candidates with
   sidecar deadlines in dev; lazy expiry continues to reclaim.
4. Enable `delete` in dev with short-lived probe streams. Verify files,
   sidecars, inventory, subscriptions, tails maps, fork retention, and recovery
   across ECS/EC2 restart.
5. Run high-cardinality scan and expiry-storm load tests.
6. Deploy production in `observe`, validate due fraction and clock/bulk guards,
   then explicitly change infrastructure to `delete`.
7. Keep `off` as rollback; it disables proactive scanning only, never lazy
   correctness or cleanup.

## Implementation slices

1. Canonical expiry math and atomic request touch/check APIs.
2. Full-ack append guard, fence, deletion cancellation, and explicit DELETE
   hardening.
3. Identity-safe registry/inventory retirement and awaited subscription cleanup.
4. Deferred meta/WAL cleanup, tails-map pruning, and recovery behavior.
5. Bounded fork/physical cleanup queue with retry and tiering guard.
6. Round-robin expiring index, scanner modes, safety valves, and metrics.
7. Deterministic race/crash tests and scale qualification.
8. Deployment flags and runbook.

## Claude Opus 5 review disposition

The first draft used a deadline heap and assumed acquiring the appender lock
waited through an append acknowledgment. Claude Opus 5 rejected that design
after reviewing the actual store, handler, WAL, tiering, and subscription paths.

Accepted blocking findings:

- The appender mutex ends before WAL wait/publish/ack; the fence must cover the
  full path.
- Delayed path-only inventory cleanup can remove a replacement entry.
- Meta sweeper/checkpoint work can recreate sidecars after unlink.
- Reaping must notify and persist subscription deletion state.
- Soft-deleted zero-reference parents and parent inventory currently leak.
- Off/observe must preserve existing lazy reclamation.
- WAL cumulative tails and dirty references require deletion cleanup.
- Existing tier/fork cleanup spawns work outside any proposed bound.

Accepted simplification:

- Physical reclamation has no sub-second SLA, so a bounded round-robin scan is
  simpler and safer than a deadline heap. Lazy lookup remains the precise
  externally observable expiry boundary.

Refinement to the review's proposed fence:

- Registry removal is delayed until in-flight append guards and the old
  stream's path-scoped subscription transition finish. This prevents an old
  path-only subscription callback from mutating a replacement stream. A `PUT`
  that discovers expiry awaits retirement and retries once, so the path is not
  permanently blocked by cleanup.

Implementation decisions:

1. A second `PUT` racing an already-fenced, non-expired retirement returns `503`
   with `Retry-After: 1`; it never downgrades an explicit deletion to expiry
   durability.
   An expired PUT may join the exact already-admitted incarnation for up to five
   seconds, then retries creation once; timeout/unavailability uses the same 503.
2. Defaults are 10,000 scans/s, 100 retirement attempts/s, and four workers.
   They remain operational starting points; infrastructure must set the mode
   explicitly and validate them under production load.
3. The coordinator admits exactly one second of configured delete work (with a
   concurrency floor), retains an admission permit across retry backoff, and
   caps active async/blocking cleanup at `--expiry-delete-concurrency`. The
   initial attempt plus five retries span about 62 seconds; a sixth failure
   terminally notifies joiners, quarantines that exact incarnation until restart,
   and releases its permit so a persistent failure cannot exhaust global
   admission. `GET /_admin/expiry` reports `quarantined_retirements`.
4. `--expiry-bulk-fraction 1.0` is the explicit bulk-delete override. Lower
   thresholds create a sticky pause only after the absolute 64-due-stream
   floor, visible through metrics and `GET /_admin/expiry`.
5. Proactive `delete` remains incompatible with S3 tiering. A persistent
   remote-GC tombstone is still a prerequisite for lifting that startup guard;
   this is a guarded future capability, not an unbounded reaper fallback.
6. A lossless full pass over recovered tombstones transfers retry ownership to
   the bounded coordinator even while failed jobs remain indexed. Live proactive
   scans therefore cannot be starved by one unreapable recovered stream.
7. Boot derives fork refcounts from successfully recovered child-to-parent
   edges. It durably reconciles stale counts before seeding zero-reference soft
   parents, while incomplete/corrupt graph evidence is handled conservatively.
   A sidecar parked as `.meta.corrupt` remains recognized on every later boot;
   its paired data and filename ID are retained and the conservative graph latch
   stays active. WAL recovery preflights those IDs before any replay mutation or
   reset, preserving retained records/tail proofs until sidecar repair.
8. Fork creation keeps the new child unpublished until its sidecar transaction
   is durable and merges only the parent refcount into the prior durable parent
   snapshot, so it cannot persist an in-flight append's speculative metadata.
9. A cascade parent already marked by active/quarantined work receives ownership
   without retaining the completed child's permit or blocking shutdown.

## Open production-hardening follow-ups

These items are open and are not waivers of the failure modes they describe.
Closing one requires the implementation and fault-injection coverage in its
acceptance criteria.

| ID | Open failure window | Acceptance criteria |
| --- | --- | --- |
| `REAPER-FU-1` | Quarantine WAL preflight uses the general durable-tails reader, which treats a missing or unreadable `tails` file as empty and skips malformed lines. If a quarantined stream's append segments have already been recycled, corrupt tails metadata can therefore hide its remaining checkpoint proof. | Add a checked recovery/preflight reader that distinguishes an absent tails file from read or parse failure and fails closed before replay or reset. Cover unreadable files, malformed/truncated lines, and a quarantined ID whose append is represented only by recycled-WAL tails evidence. |
| `REAPER-FU-2` | Unpublished fork creation compensates a durably incremented parent refcount and removes child artifacts after a later create failure, but those compensation writes and unlinks can themselves fail. The result can be a conservative phantom parent reference or recoverable unpublished child artifacts until restart reconciliation/operator repair. | Give create rollback an explicit durable recovery state (or an equivalent idempotent transaction) so every write/fsync/rename/unlink fault combination converges after restart. Fault-inject each boundary and prove that no child becomes append-visible early, no live child loses its parent reference, and no phantom reference remains after recovery. |
| `REAPER-FU-3` | Reaper shutdown stops admission and drains existing work, but `Handle::shutdown` has no overall deadline. A stuck filesystem operation or indefinitely delayed admitted cleanup can therefore hold graceful process shutdown forever. | Add a configurable wall-clock drain deadline that reports timeout to the caller, leaves unfinished streams fenced and recoverable, and exposes the timeout in logs/telemetry. Cover a held blocking cleanup and prove bounded return without clearing the exact retirement marker or losing the durable tombstone. |
