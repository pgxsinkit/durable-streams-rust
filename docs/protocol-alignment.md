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
