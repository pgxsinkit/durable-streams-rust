# Provenance

This repository is a fork of ElectricSQL's Rust Durable Streams server, extracted from the
`electric-sql/electric` monorepo.

## Fork point

| | |
|---|---|
| Upstream repo | `electric-sql/electric` |
| Upstream commit | `dc07a1e6c8ff459b59ce407cdb6bf2f7fd068f36` (2026-08-21, `main`) |
| Upstream path | `packages/durable-streams-rust` |
| Tree hash | `af3df4adb7023db36ba8aae8d8321deab1a5c43c` |
| Version at fork | `0.1.5` |
| License | Apache-2.0 (see `LICENSE`, `NOTICE`) |

`main` is the extraction, byte-identical to the upstream subdirectory at that commit. History was
rewritten with `git-filter-repo` over both the current path and its pre-rename predecessor
(`packages/server-rust`), so all 13 upstream commits are preserved back to the original import
(`feat(server-rust): Rust Durable Streams server`, upstream #4652). Work happens on `develop`.

## Why this fork exists

Not because of an outstanding bug. At the fork point there were **no open correctness issues**
against the server — the durability work (see `CRASH_SIM_FINDINGS.md`) landed in 0.1.4/0.1.5, and
the three open upstream issues (#4695, #4696, #4706) are scale/architecture items that do not bite
below ~100k streams.

The fork is a supply-chain move. The published artifacts — the `durable-streams` crate on crates.io,
the `@electric-ax/*` npm packages, and the `electricax/durable-streams-server-rust` Docker Hub image
— were **all published from `electric-sql/electric`'s CI**, under namespaces belonging to Electric
the company, which was acquired by Databricks in August 2026. There is no second publisher: the
attempt to move crates.io publishing into `durable-streams/durable-streams` (PR #389 there) was
closed unmerged, and the PR that would have given the server a home in that repo (#387) has been
open since 2026-06-13 without maintainer review. If that CI or those namespaces go away, nothing
else builds these artifacts.

So this repo exists to own the build, not to take over development.

## What changed from upstream

Only provenance and packaging metadata:

- Added `LICENSE` (Apache-2.0) and `NOTICE`. Neither existed in the subdirectory — the license lived
  at the monorepo root, so the extraction would otherwise have shipped unlicensed.
- `Cargo.toml`: `repository` pointed at `durable-streams/durable-streams`, which has never contained
  this code. Now points here. This is why the crates.io listing for `durable-streams` links to a repo
  where the server does not exist.
- `package.json`: `repository` retargeted from the monorepo + `directory` to this repo.
- `README.md`: protocol-spec links were monorepo-relative (`../../PROTOCOL.md`); now absolute.
- `Dockerfile`: `COPY` paths were monorepo-relative and the build context was the monorepo root;
  both are now repo-relative. Base image pinned to `rust:1.96.0-bookworm` (was `rust:1-bookworm`).
- Added `rust-toolchain.toml` pinning rustc 1.96.0, matching `pgxsinkit/electric-circuits` so both
  Rust services build on one toolchain. Circuits pins that version because rustc >= 1.97.0 ICEs on
  `dbsp`; this crate has no dbsp and a declared MSRV of 1.75, so it is held here only for parity.
- Added `.github/workflows/ci.yml` and `docker.yml`, ported from the monorepo (see below).
- `.gitignore` now covers `node_modules`, which the monorepo root used to.

Deliberately **not** changed: crate name, npm package names, and the version. Publish identity is a
decision, not a mechanical fix — see below.

Known cosmetic breakage carried over: `bench-latency/latency-probe.mjs` imports the client through a
sibling package's `node_modules`, which never resolved outside the monorepo.

## Conformance status

The protocol conformance suite is this fork's contract. Measured at the fork point (release build,
rustc 1.96.0):

| suite version | result |
|---|---|
| `0.3.5` — the last version upstream ever ran | **326 passed, 0 failed**, 6 skipped |
| `0.3.6` — current | 329 passed, **3 failed**, 6 skipped |

The extraction is therefore clean: no regressions. `0.3.6` was published 2026-07-16, two days after
the last upstream commit to this server, and `package.json` carried a caret range, so upstream CI
never ran the six tests it added. Three of them fail — inherited gaps upstream will not fix:

- **#1** — a close-only `POST` does not slide the TTL window (two tests).
- **#2** — `OPTIONS` preflight returns no CORS headers at all (one test).

The dependency is pinned to an exact version rather than a caret range, so moving the contract is a
visible commit rather than an install-time surprise. The later protocol-alignment pass closed both
inherited gaps, enabled the reserved-subscription suite, and brought the current result to **338
passed, 0 failed, 0 skipped**. See `docs/protocol-alignment.md`; the table above remains the measured
fork-point baseline. That pass also moved `reqwest` from a test-only dependency to a runtime
dependency for outbound webhook delivery and added direct `ring` use for Ed25519 signatures and
fenced callback tokens; these are intentional production dependency-surface changes.

## Open decisions

- **Publish identity.** The crate is `durable-streams` on crates.io and the npm packages are
  `@electric-ax/*`; both are upstream's. Publishing from here needs different names, or no registry
  publishing at all. Upstream's publish workflow was deliberately **not** ported for this reason.
- **Multi-arch images.** Upstream built `linux/amd64` + `linux/arm64` natively per arch. `docker.yml`
  here builds amd64 only, matching `electric-circuits`. QEMU-emulated arm64 Rust builds are slow
  enough that upstream avoided them, so adding arm64 wants native runners, not just a `platforms:` line.
- **Stranded upstream PRs**, all unmerged against `electric-sql/electric` and all by the original
  author: #4667 (serve caught-up long-polls from the epoll reactor), #4709 (io_uring write paths,
  default off, measured as a regression as submitted), #4686 (replicated durability via openraft).

## Relationship to the protocol

The Durable Streams **protocol** is maintained separately at `durable-streams/durable-streams`
(mirrored at `pgxsinkit/durable-streams`), along with the conformance suite this repo tests against
(`@durable-streams/server-conformance-tests`, an npm devDependency) and the client that consumes it.
That mirror is deliberately kept at zero commits ahead so it can fast-forward from upstream.

The conformance suite is the contract worth holding onto: it is what makes this server replaceable
by another implementation if maintaining Rust ever stops being worth it.

## Syncing from upstream

```sh
git remote add upstream https://github.com/electric-sql/electric.git   # already configured
git fetch upstream
# Extract the subdirectory at the new upstream commit, then rebase onto it.
# Never merge — history here stays linear.
```
