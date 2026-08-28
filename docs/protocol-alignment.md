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

## Important limits of that coverage

Passing the six subscription tests is not the same as completing every
production requirement in protocol sections 6–7. The current implementation
matches the upstream reference server's process-lifetime behavior, with these
known gaps:

- Subscription definitions, acked offsets, generations, leases, retry
  schedules, and signing/token keys are process-local. The protocol requires
  durable cursor state and persisted retry metadata. A restart currently loses
  subscriptions rather than resuming pending work.
- Pull-wake events themselves are durable: they are appended through the normal
  JSON stream/WAL path. The metadata deciding whether another wake is needed is
  not yet durable.
- The protocol specifies service-JWT authorization for `claim`; the upstream
  conformance test sends no authorization and this implementation does not yet
  validate one. Deployments must keep the control prefix behind the existing
  access boundary until this is implemented. The mTLS access policy requires a
  separate rule with `"control": true`; ordinary data-prefix rules never match
  `__ds`, and the example policy grants no subscription control access by
  default.
- Webhook validation rejects literal private/link-local IPs, permits only the
  documented localhost HTTP exception, rejects IPv6 literals, and disables
  redirects. It does not yet pin DNS resolution to public addresses, so
  production-grade SSRF protection remains incomplete.
- Webhook signing keys are generated at process start. Protocol-compliant key
  persistence and rotation (including retaining old JWKS entries through the
  replay window) remain to be implemented.
- `DS_PUBLIC_BASE_URL` is mandatory for webhook subscriptions. It must be a
  trusted origin URL (HTTPS except for `localhost`/`127.0.0.x` development), so
  callback and JWKS URLs never derive from attacker-controlled `Host` or
  forwarding headers.

Pull-wake creation also requires its ordinary JSON `wake_stream` to exist and
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
