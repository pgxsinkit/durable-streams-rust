# Durable Streams server (Rust)

[Durable Streams](https://github.com/durable-streams/durable-streams/blob/main/PROTOCOL.md) is an open protocol for persistent, resumable event streams over plain HTTP — the data primitive for the agent loop.

This is a Rust implementation of that protocol. It's a single self-contained binary with no database, broker, or other moving parts — just a process and a data directory. It stores each stream as the literal bytes it puts on the wire, so reads are byte ranges of a file.

## Install

Three ways to get the server (Linux/macOS, x64/arm64):

```bash
# 1. cargo (builds the binary `durable-streams-server`)
cargo install durable-streams

# 2. npm (downloads a prebuilt binary for your platform)
npm install -g @electric-ax/durable-streams-server-rust

# 3. Docker (multi-arch image)
docker run -p 4437:4437 electricax/durable-streams-server-rust
```

cargo and npm both install the `durable-streams-server` command; the Docker image
runs it directly.

## Quickstart

**Build prerequisites:** a Rust toolchain — stable, **≥ 1.75** (the MSRV; edition
2021). Just `cargo`/`rustc` + a C linker; no system libraries and no default cargo
features. Builds on Linux and macOS, x64 and arm64.

```bash
# build (run from packages/durable-streams-rust)
cargo build --release        # → ./target/release/durable-streams-server
cargo test  --release        # unit + integration tests (protocol conformance: see Conformance below)

# run
./target/release/durable-streams-server --port 4438 --data-dir ./data
```

Create a stream, append to it, read it back:

```bash
BASE=http://localhost:4438/my-stream

curl -X PUT  "$BASE" -H 'Content-Type: application/octet-stream'        # create
curl -X POST "$BASE" -H 'Content-Type: application/octet-stream' \
     --data 'hello;'                                                    # append
curl         "$BASE"                                                    # read -> hello;
curl -I      "$BASE"                                                    # HEAD (offset, length)
```

Read live as data arrives:

```bash
curl "$BASE?offset=now&live=long-poll"   # blocks until the next append (or timeout)
curl -N "$BASE?offset=0&live=sse"        # Server-Sent Events stream
```

## Private mTLS access sidecar

The WAL deployment keeps `durable-streams-server` on `127.0.0.1:4437` and exposes a separate
`durable-streams-access` process on the task's private network. The sidecar requires TLS 1.3 client
certificates, maps certificate URI SANs to configured service identities, authorizes a canonical
method/path pair, applies separate data/admin and per-identity capacity, then streams the request
and response to the loopback server without buffering either body. TLS handshakes are globally
bounded; after authentication, established connections are bounded per identity so an agent
workload cannot consume the Circuits or storage-administrator connection budget.
Admin-capable identities declare explicit reservations whose sum cannot exceed the global admin
pool, so one admin caller cannot consume another caller's share. Long-poll and SSE have separate
response deadlines; the example policy allows the server's 60-second SSE session to finish before
the proxy closes it.

```bash
durable-streams-access \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:4437 \
  --server-cert /run/secrets/server.pem \
  --server-key /run/secrets/server.key \
  --client-ca /run/secrets/client-ca.pem \
  --policy /etc/durable-streams/access-policy.json
```

[`deploy/access-policy.example.json`](deploy/access-policy.example.json) is the fixed internal-pilot
capacity and path-policy profile. Unknown fields, duplicate certificate identities, overlapping
rules, encoded/dot-segment aliases, missing certificate identities, and unavailable capacity all
fail closed. Build the sidecar image with `Dockerfile.access`; release CI publishes it as the
`-access` sibling of the storage image.

## Flags

`durable-streams-server [flags]` — every flag is optional. The defaults give a
durable, single-node server on `127.0.0.1:4437` with its data dir under `$TMPDIR`.

**Network & storage**

| Flag                     | Default                        | Description                                                     |
| ------------------------ | ------------------------------ | --------------------------------------------------------------- |
| `--host`                 | `127.0.0.1`                    | listen address (use `0.0.0.0` to accept remote connections)     |
| `--port`                 | `4437`                         | listen port (the protocol default, PROTOCOL.md §13.1)           |
| `--data-dir`             | `$TMPDIR/durable-streams-rust` | storage directory. **Required with `--durability wal`** — the default is a temp dir, so wal would fsync every append and discard it on restart; the server refuses that combination at startup rather than let it look healthy. Optional in `memory` mode, which makes no durability claim. |
| `--long-poll-timeout-ms` | `30000`                        | how long a `live=long-poll` request blocks before returning 204 |

**Durability** — controls how appends are made durable. See [ARCHITECTURE.md › Durability modes](ARCHITECTURE.md#durability-modes).

| Flag                  | Default   | Description                                                                                                                                                                                                                                                                                                               |
| --------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--durability`        | `wal`     | `wal` (default) — durable group-commit `fdatasync`; an append acks only after its record is in the sharded WAL. `memory` — no WAL, no fsync; the same buffered append path with the WAL stage/wait skipped, ack on the page-cache write; **NOT locally crash-durable** — durability is delegated to (future) replication. |
| `--wal-shards`        | CPU cores | (`wal` mode) shard / group-commit-committer count; persisted on first run, a later run must match it                                                                                                                                                                                                                      |
| `--wal-segment-bytes` | `128 MiB` | (`wal` mode) per-shard WAL segment size; lower it only to force segment rolls in tests/benches                                                                                                                                                                                                                            |

**Read path** — performance knobs; none change protocol behaviour. Leave at defaults unless a benchmark says otherwise.

| Flag                 | Default                       | Description                                                                                                                                                                                                       |
| -------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--tail-cache-bytes` | `0` (Linux) / `65536` (macOS) | resident tail-cache cap in bytes; `0` disables it (every read resolves to the file via `sendfile`/`pread`). Off by default on Linux (`sendfile` is already fast), on by default on macOS (no `sendfile`).         |
| `--read-offload`     | `tail`                        | Linux: where `sendfile` reads run — `inline` (async worker), `tail` (live tail inline, catch-up on the blocking pool), `always` (blocking pool). `tail` keeps a cold backfill's disk fault off the async workers. |

**Cold-storage tier** — off by default; see [Tiered storage](#tiered-storage-cold-offload). With `--tier off` the server is byte-identical to a single-file deployment.

| Flag                                          | Default    | Description                                              |
| --------------------------------------------- | ---------- | -------------------------------------------------------- |
| `--tier`                                      | `off`      | `off` \| `s3` (S3-compatible object storage)             |
| `--tier-endpoint`                             | —          | (`tier=s3`) S3 endpoint URL                              |
| `--tier-region`                               | —          | (`tier=s3`) region                                       |
| `--tier-bucket`                               | —          | (`tier=s3`) bucket name                                  |
| `--tier-key-prefix`                           | —          | object-key prefix for sealed segments                    |
| `--tier-segment-bytes`                        | `8 MiB`    | sealed-segment size (fixed-size, CDN-friendly)           |
| `--tier-compact-bytes`                        | `64 MiB`   | small-segment compaction threshold                       |
| `--tier-path-style` / `--tier-virtual-hosted` | path-style | S3 addressing style                                      |
| `--tier-allow-http`                           | off        | allow plain HTTP to the S3 endpoint (e.g. a local MinIO) |

S3 credentials come from the **environment**, never flags: `DS_S3_ACCESS_KEY_ID` /
`DS_S3_SECRET_ACCESS_KEY` (or the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).

### Choosing a configuration

| Your situation                                      | Use                                                                                            |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Bounded local disk with long history**            | `--tier s3` — seal cold segments to object storage; the recent tail stays local and zero-copy. |
| **High fan-out p99 across many streams on Linux**   | try `--tail-cache-bytes 65536` (off by default there because `sendfile` already covers it).    |
| **Experimenting on macOS and writes take ~2–10 ms** | expected — see [macOS write latency](#macos-write-latency-f_fullfsync) below.                  |

### macOS write latency (`F_FULLFSYNC`)

In `wal` mode every acked append is durable, and on macOS that durability
barrier is `fcntl(F_FULLFSYNC)` — a true flush of the drive's write cache. A
plain macOS `fsync()` does **not** survive power loss, so the server pays the
real barrier, and it costs **~2–10 ms per group commit** depending on the disk
(measured ~3 ms on an M-series laptop SSD). On Linux this doesn't apply:
`fdatasync` already issues the device barrier and is cheap on NVMe.

So if you're benchmarking or demoing on a Mac and every write (and therefore
every live read) shows a few milliseconds of latency: that's the disk barrier,
not the server. Options, in order of preference:

1. **`--durability memory`** — the honest "I don't need power-loss durability"
   mode; write acks drop to ~0.2–0.5 ms.
2. **`DS_UNSAFE_FAST_FSYNC=1`** (env var, bench-only) — keeps `wal` mode but
   swaps `F_FULLFSYNC` for a plain `fsync`, approximating the Linux/NVMe
   regime on a Mac (~0.3 ms acks). The WAL machinery still runs; only the
   final barrier is weakened. A no-op on Linux. **Never set this in
   production**: a power failure can lose acked writes, which silently breaks
   the `wal`-mode contract (process/OS crashes are still fine).

### Run-configuration matrix

Every run configuration — durability (`wal` vs `memory`), resident tail cache
on/off, read-offload — is **protocol-equivalent**, and CI runs the full
conformance suite once per configuration (the `conformance` matrix in
`.github/workflows/ci.yml`; flags are passed via `RUST_SERVER_ARGS`, e.g.
`RUST_SERVER_ARGS="--durability memory" bun run test:conformance`).

## What it implements

Core protocol: create / append / read (catch-up, long-poll, SSE), HEAD, DELETE, JSON mode, idempotent producers (`Producer-Id` / `Producer-Epoch` / `Stream-Seq`), close, TTL / expiry, cursors, ETags / 304, security headers, and stream forks.

Reserved subscription APIs: webhook and pull-wake subscriptions, glob/explicit membership, Ed25519/JWKS webhook signing, callback fencing, and claim/ack/release leases. Pull-wake lets a worker tail one wake stream and fetch only source streams with pending work; it does not multiplex the source payloads themselves onto that connection. Subscription definitions, cursors, generations, leases, retry deadlines, callback-token secrets, and webhook signing keys are crash-safe and resume across restarts. See [protocol alignment and production behavior](docs/protocol-alignment.md).

Webhook subscriptions require `DS_PUBLIC_BASE_URL` to be set to the trusted
external origin, for example `https://streams.internal.example`. Pull-wake
subscriptions require an existing open `application/json` wake stream. When
using `durable-streams-access`, subscription routes are denied by ordinary data
rules and require an explicit rule such as:

```json
{
  "match": "prefix",
  "path": "/circuits/v1/dev/stores/replace-with-store-generation/",
  "methods": ["GET", "PUT", "POST", "DELETE"],
  "control": true
}
```

Do not grant that rule until the identity is intended to manage subscriptions.
Pull-wake `claim` also fails closed unless service-JWT verification is
configured:

| Environment variable | Required | Purpose |
| --- | ---: | --- |
| `DS_SUBSCRIPTION_SERVICE_JWT_JWKS_FILE` | yes | Mounted asymmetric JWK Set; atomically replacing the file rotates trusted service keys without restarting. |
| `DS_SUBSCRIPTION_SERVICE_JWT_ISSUER` | yes | Exact required `iss` claim. |
| `DS_SUBSCRIPTION_SERVICE_JWT_AUDIENCE` | yes | Exact required `aud` claim. |
| `DS_SUBSCRIPTION_SERVICE_JWT_REQUIRED_SCOPE` | no | Required member of a space-delimited or array-valued `scope` claim. |
| `DS_SUBSCRIPTION_SERVICE_JWT_REQUIRED_SUBJECT` | no | Exact required `sub` claim, for binding claims to one service identity. |
| `DS_WEBHOOK_SIGNING_KEY_ROTATION_SECS` | no | Webhook signing-key lifetime; default 30 days, `0` disables automatic rotation. |
| `DS_WEBHOOK_SIGNATURE_REPLAY_WINDOW_SECS` | no | How long rotated public keys remain in JWKS; default 5 minutes. |
| `DS_WEBHOOK_ALLOW_LOCALHOST` | no | Set to `1` only in development to permit HTTP callbacks to `localhost`/`127.0.0.0/8`. |

JWT verification accepts asymmetric RS256/384/512, PS256/384/512,
ES256/384, and EdDSA keys, and requires a valid signature, `exp`, issuer, and
audience. `DS_SUBSCRIPTION_INSECURE_ALLOW_UNAUTHENTICATED_CLAIMS=1` is an
explicit development/conformance escape hatch and must not be set in
production.

Webhook delivery resolves DNS itself, rejects the request if any answer is
private/local, and pins the selected public address into a no-proxy,
no-redirect HTTP client while retaining the hostname for TLS SNI and `Host`.
Plain HTTP and loopback targets are rejected unless the explicit localhost
development flag is set.

Durable: in `wal` mode (the default), an append returns only after its record is durable in the sharded write-ahead log (WAL). The WAL acks on a group-commit `fdatasync` and recovers cleanly on restart: every WAL record carries both a header CRC32C (torn-header detector — a partially-written header fails immediately) and a payload CRC32C verified on recovery, so no torn or zeroed record is ever replayed. State survives restarts — on boot the store rebuilds every stream from its data file plus a `.meta` sidecar, re-links fork chains, and replays the WAL to reconcile any un-checkpointed tail. (Crash window per [PROTOCOL.md](https://github.com/durable-streams/durable-streams/blob/main/PROTOCOL.md): producer dedup state may lag the data file, so producers should bump their epoch on restart.)

In `memory` mode there is no WAL and no WAL replay. Recovery is a sidecar pass: each stream is rebuilt from its per-stream data file and `.meta` sidecar; durability is delegated to (future) replication.

## How it's built

- **Contiguous wire-byte storage** — each stream's data file holds exactly the bytes that go on the wire, so a catch-up read is a literal byte range. No reframing, no per-message copies.
- **Sharded WAL durability** — in `wal` mode (the default), appends are acked only after their record is durable in the sharded write-ahead log. One group-commit committer per shard batches many streams' appends into a single `fdatasync` (`F_FULLFSYNC` on macOS), minimizing fsync operations regardless of stream cardinality. Per-stream files are the read view; checkpoint periodically fsyncs them and recycles WAL segments. See [Durability](ARCHITECTURE.md#durability).
- **Per-stream serialization, lock-free reads** — one async mutex per stream orders appends; reads take a brief snapshot and do positioned `pread`s, never blocking the writer.
- **watch-channel wakeups** drive long-poll and SSE subscribers, so there's no polling loop.
- **A single, hand-rolled HTTP/1.1 engine** — no framework: it owns the socket, so on Linux it serves reads with `sendfile(2)` (zero-copy page cache → socket, ~10× less CPU per byte); elsewhere it falls back to positioned reads.

## Tiered storage (cold offload)

Opt-in (`--tier`, off by default). Because streams are append-only and immutable by position, the server can break a stream into fixed-size, CDN-friendly **segments** (`--tier-segment-bytes`, default 8 MiB): once data leaves the hot tail it is **sealed** and offloaded to object storage, and catch-up reads of cold history are served from there. Recent data stays local (the hot tier, served zero-copy as today). With `--tier off` the server is byte-identical to a single-file deployment.

The `s3` backend works with any S3-compatible endpoint — Cloudflare R2, Fly/Tigris, MinIO, Backblaze B2 — behind the **`tier` Cargo feature** (a default build pulls no object-storage dependencies): `cargo build --release --features tier`. Flags are in the [table above](#flags); credentials come from the environment only. Durability is unchanged — an append still acks only after the local fsync; offload is strictly post-durability. The seal/upload/manifest lifecycle, crash-safe live-file compaction, and CDN/GC behaviour are documented in [ARCHITECTURE.md › Tiering](ARCHITECTURE.md#tiering-hot-buffer--cold-storage-optional). Conformance passes with tiering on as well as off (a manual check — the CI matrix runs the default, tier-less build).

## Observability (OpenTelemetry)

Opt-in via the **`telemetry` Cargo feature** (off by default — a default build pulls no OpenTelemetry dependencies and adds zero hot-path overhead): `cargo build --release --features telemetry`. Configured entirely by the standard `OTEL_*` env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_SAMPLER`, …); spans + metrics export over OTLP/gRPC.

The instrumentation is deliberately lean and aimed at finding bottlenecks: a single `ds.request` span (bounded attributes only — never the stream path/id) plus metrics. The two most useful are **`ds.append.fsync.batch_size`** (group-commit health — how many appends fold into one fsync) and **`ds.read.offload.wait`** (blocking-pool queue wait, the cold-read pressure signal); alongside append fsync/lock-wait/total duration, read duration by mode, tail-cache hit ratio, and a request counter. All labels are bounded (engine, live, cache, outcome, …).

## Conformance

```bash
bun install
cargo build --release          # the harness spawns target/release/durable-streams-server
bun run test:conformance

# or against an already-running server:
RUST_SERVER_URL=http://localhost:4562 bun run test:conformance
```

The complete published conformance `0.3.6` contract passes: **338 passed, 0 failed, 0 skipped**, including all six reserved-subscription tests. The exact upstream revision, covered behavior, and protocol requirements not exercised by that suite are recorded in [docs/protocol-alignment.md](docs/protocol-alignment.md).

## Releasing

Released via Changesets to three channels — crates.io (`durable-streams`), npm
(`@electric-ax/durable-streams-server-rust`, currently gated off), and Docker Hub
(`electricax/durable-streams-server-rust`). See [RELEASING.md](RELEASING.md).

---

## Benchmarks

Numbers from **[ds-bench](https://github.com/electric-sql/ds-bench)**, a reproducible single-node harness — the maintained results are the **[canonical campaign report](https://github.com/electric-sql/ds-bench/blob/main/results/REPORT.md)** (latest: 2026-07-23, measured on the `0.1.5` release with the barrier-aligned saturation methodology). Server on one `c4d-standard-64-lssd` node (raw-block local NVMe, the WAL_TUNING.md split-lane layout) pinned to **8 CPUs**; a Kubernetes client fleet drives 256-byte binary appends. Throughput is the saturation ceiling; latency is fleet-wide p50 / p99; memory is the pod cgroup working set (anon + active page cache), peak / p50.

**Writes** (`wal` mode, group-commit fsync, the WAL_TUNING.md ideal configuration) — **~422k append/s at 10k streams and ~388k at 100k** on 8 pinned CPUs (**no cardinality cliff**: −8% from 10k→100k), with p50 append latency ~2.5 ms at ≤80% load. `memory` durability (the no-fsync ceiling) measures ≥636k at 100k streams on the same box. Past the fsync fixes the write path is CPU-bound: **16 pinned cores reach ~537k append/s** (true plateau). Memory tracks **stream count, not bytes** (each stream is a lean record plus its open file; data lives on disk / in the page cache, never resident), so the pod working set stays in the hundreds of MiB even at 100k streams — versus the 1–3.5 GB a log-resident design holds at the same load.

**Reads** — catch-up replay sustains **~2.8 GiB/s** aggregate at 512 concurrent connections, flat from 10 to 100 streams; SSE live tail holds its delivery rate flat to 2048 concurrent connections; and interference stays decoupled: **100k concurrent paced catch-up readers cost a pinned 50k append/s write load nothing** (zero errors, write throughput unchanged). Single-stream fan-out (subscriber ladder) numbers — **fan-out memory is shared, not per-subscriber**: 1000 SSE subscribers on one stream cost ~27 MiB total — are from the **[2026-06-30 snapshot](https://github.com/electric-sql/ds-bench/blob/main/results-2026-06-30/REPORT.md)**.
