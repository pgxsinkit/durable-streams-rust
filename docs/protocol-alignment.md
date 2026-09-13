# Durable Streams protocol alignment

Audited against:

- Protocol: [DRAFT Durable Streams Protocol 1.0](https://github.com/durable-streams/durable-streams/blob/main/PROTOCOL.md)
- Upstream repository commit: `a172acc389351cb3db6deb5cd60e3dec11e7ff39`
- Published conformance suite: `@durable-streams/server-conformance-tests@0.3.6`

The published package and upstream `main` contain the same conformance source at
that commit. There is no newer unpublished suite in the upstream repository.

This file records the places where the protocol leaves a decision to the server
and this implementation had to make one. It is not a coverage report — the
conformance result for this server is in the README.

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
