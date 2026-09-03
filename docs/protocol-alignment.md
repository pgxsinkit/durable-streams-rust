# Durable Streams protocol alignment

Audited 2026-08-28 against:

- Protocol: [DRAFT Durable Streams Protocol 1.0](https://github.com/durable-streams/durable-streams/blob/main/PROTOCOL.md)
- Upstream repository commit: `a172acc389351cb3db6deb5cd60e3dec11e7ff39`
- Published conformance suite: `@durable-streams/server-conformance-tests@0.3.6`

The published package and upstream `main` contain the same conformance source at
that commit. There is no newer unpublished suite in the upstream repository.

## Executable coverage

| Surface | Enabled | Result |
|---|---:|---:|
| Core stream protocol | yes | 332 passed |
| Reserved subscription APIs | yes | 6 passed |
| Total | yes | **338 passed, 0 failed, 0 skipped** |

The subscription cases exercise:

- create, idempotent re-confirmation, read, and delete;
- Ed25519 webhook signatures and JWKS discovery;
- rejection of literal unsafe webhook IP URLs;
- synchronous webhook auto-ack and callback generation fencing;
- additive/removable explicit stream membership; and
- pull-wake claim, ack, release, and competing-worker leases.

Run the exact contract with:

```bash
cargo build --release
bun run test:conformance
```

The harness resolves Cargo's configured target directory, bootstraps the WAL
store identity when needed, and enables the subscription suite.

## Chunked catch-up reads (§5.6)

Section 5.6 defines a catch-up read as returning bytes from the requested offset
"up to a server-defined maximum chunk size", with `Stream-Next-Offset` as the
cursor for the next request. `Stream-Up-To-Date: true` MUST be present only when
the response includes all data available at that moment and "SHOULD NOT be
present when returning partial data due to server-defined chunk size limits";
`Stream-Closed` likewise belongs to the response that reaches the final offset
and "SHOULD NOT be present when returning partial data from a closed stream".

This server previously defined no maximum: one `GET` returned the entire
remainder of a stream, so a client that buffers and parses a response scaled its
memory with the stream rather than with the request (measured: a single 65.6 MB
JSON response of 9,421 items; four concurrent readers of a 250 MB stream killed
a 3 GiB process).

Reads are now bounded by `--max-chunk-bytes` (env `DS_MAX_CHUNK_BYTES`), default
**4 MiB** — the same per-response budget the upstream reference server applies
(`MAX_READ_BATCH_BYTES` in `packages/server-cloudflare/src/stream-object.ts`), so
a paginating client sees the same page sizes here as upstream. `0` restores the
previous unlimited behavior for operators who want it.

A capped page:

- ends on a boundary that keeps the response well-formed. Byte streams cut at
  any byte — no read and no scan, so that path stays zero-copy. JSON streams cut
  only just past a top-level value separator, using the same value-boundary
  scanner the tiering path uses to seal segments, so every page is a whole number
  of values and still parses as a JSON array. A single value larger than the cap
  is returned whole rather than split — a page with data available is never
  empty. Locating that boundary reads the page, so those bytes are the ones
  served: a capped JSON page is read once, not once to scan and once to send
  (which on a cold tier would be an extra range read per page), and the scan
  walks forward in cap-sized windows so an oversize value is located without
  re-reading what it already scanned.
- reports the aligned end as `Stream-Next-Offset`, omits `Stream-Up-To-Date`, and
  omits `Stream-Closed` (a closed stream is closed *to the reader* only once the
  page that reaches the tail is delivered). The `ETag` covers the range actually
  returned, so a partial page and a later full-tail page never share a validator.

Two invariants the cut depends on:

- **A read range starts on a value boundary.** Server-minted offsets, tier cuts
  and fork points all do. `Stream-Fork-Sub-Offset` counts *messages*, so it is
  resolved with the same top-level value scanner rather than by counting raw
  commas — a comma inside a string or a nested array is not a message boundary,
  and a fork point placed inside a value would make every later read of that
  fork malformed JSON.
- **A range that provably is not value-aligned is refused, not served.** If the
  scanner reaches the tail of a JSON range without finding a single top-level
  separator, the requested offset is inside a value (§8 leaves client-fabricated
  offsets undefined). Falling back to the uncapped tail — serving an unbounded,
  malformed page and marking it up to date — is exactly the failure the cap
  exists to prevent, so the request is refused with `400` and logged instead. A
  window that cannot be read (cold-storage error) is refused with `503` rather
  than framed around bytes that cannot be served.

The cap applies to long-poll responses too: chunk semantics are a property of a
read, and a woken long-poll consumer is often the one furthest behind. The
client already advances by `Stream-Next-Offset`, and the omitted
`Stream-Up-To-Date` tells it to come straight back for the remainder.

SSE is already an incremental framing, but its catch-up is a read like any
other: a subscriber starting at `offset=0`, or reconnecting far behind the tail,
used to materialize and encode the whole backlog into one event (the inline
producer read `[pos, tail)`; the Linux reactor allocated `tail - write_off`
before its pending-size check). Both paths now emit the backlog as successive
data/control pairs of at most the cap, with `upToDate` false until the frame
that reaches the tail — so `--max-chunk-bytes` bounds read memory on every read
path, which is what the flag claims. A capped `text/*` frame is additionally
backed off to a UTF-8 character boundary, because that encoding is lossy and a
split multi-byte character would corrupt both halves.

CI runs the published conformance suite once more with `--max-chunk-bytes 4096`
(the `wal-small-chunk` matrix entry) so the contract is exercised with chunking
forced on nearly every read.

## Production behavior beyond the published fixture

The six upstream subscription cases do not exercise restart and deployment
security behavior. This implementation additionally provides:

- Crash-safe atomic snapshots under `<data-dir>/subscriptions/state.json` for
  subscription definitions, acked offsets, generations, wake snapshots,
  leases, retry counts, and absolute `next_attempt_at` deadlines. Files and
  directories are owner-only and each replacement is file-fsynced, renamed,
  and parent-directory-fsynced before a state-changing HTTP response returns.
  Append-derived wake/link snapshots are coalesced onto a blocking writer and
  are reconstructed from recovered stream inventory if a crash wins that
  small window. A background transition that cannot be persisted fails the
  process instead of continuing with split memory/disk truth.
- Startup resume after stream/WAL recovery. Unexpired leases retain their
  holder and fencing token, expired leases produce a later generation, and
  failed deliveries honor the remaining persisted backoff. A crash between an
  external delivery and its local state commit can replay the same fenced
  `wake_id`, giving at-least-once delivery without cursor loss.
- Persistent callback-token and Ed25519 private keys under
  `<data-dir>/subscriptions/secrets.json`. Rotation first durably prepublishes
  a new public key for the five-minute JWKS cache lifetime, activates it only
  afterward, and retains the prior key through the configured signature replay
  window. The server refuses to replace missing secrets when state exists.
- Fail-closed service-JWT validation for pull-wake `claim`: a mounted JWKS file,
  exact issuer, and exact audience are required, with an optional required
  scope and subject. A validated JWKS is cached for at most one second, so
  atomic replacement rotates trust without making attacker-controlled claims
  force disk reads. Only asymmetric signing keys whose `alg`, `use`,
  `key_ops`, family, and curve authorize the token algorithm are accepted.
- DNS-rebinding-resistant webhook delivery. Every attempt resolves the target,
  rejects mixed or exclusively private/local answers, disables redirects and
  proxies, and pins a validated address into the HTTP client while retaining
  the original hostname for TLS verification.
  DNS and total-request timeouts, a 64 KiB response limit, bounded pinned-client
  reuse, and explicit rejection of transition/embedded-address IP ranges keep
  retrying endpoints resource-bounded.

The published conformance claim request does not yet carry its specified
service JWT, so the repository harness alone sets
`DS_SUBSCRIPTION_INSECURE_ALLOW_UNAUTHENTICATED_CLAIMS=1`. It also sets
`DS_WEBHOOK_ALLOW_LOCALHOST=1` for its loopback fixture. Normal server startup
does not enable that bypass: an unconfigured claim endpoint returns `503`, and
missing, invalid, or insufficient credentials return `401`/`403`.

`DS_PUBLIC_BASE_URL` remains mandatory for webhook subscriptions. It must be a
trusted origin URL (HTTPS except when the explicit localhost development flag
permits `localhost`/`127.0.0.0/8`), so
callback and JWKS URLs never derive from attacker-controlled `Host` or
forwarding headers.

Pull-wake events are appended through the normal JSON stream/WAL path. Creation
requires that ordinary JSON `wake_stream` to exist and
remain open. A subscription never links its own wake stream, even when a glob
such as `**` would otherwise match it. Failed wake writes retry with bounded
exponential backoff rather than permanently wedging the generation.

The storage process does not grant browser origins by default. `OPTIONS`
advertises the protocol request headers for compatibility testing, but no
`Access-Control-Allow-Origin` is emitted. Browser access should be enabled with
an explicit origin allowlist at the authenticated edge.

Finally, these subscription APIs multiplex the *wake/cursor control plane*, not
stream payload bytes. A worker can tail one durable wake stream instead of
holding one idle long-poll per source stream, then read only the streams named
by a successful claim. If one connection must carry all payloads directly, that
is a separate multi-read/SSE envelope extension and is not part of protocol 1.0.
