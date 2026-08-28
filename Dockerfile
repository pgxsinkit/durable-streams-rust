# syntax=docker/dockerfile:1
#
# Built and published by .github/workflows/docker.yml to
# ghcr.io/pgxsinkit/durable-streams-rust. The build context is the repo root.
#
# Upstream this lived in a monorepo, so the COPY paths were prefixed with
# `packages/durable-streams-rust/` and the context was the monorepo root. This
# repo IS the package, so the paths are repo-relative.

# ---- build stage: compile the release binary (glibc, matches the runtime) ----
# Pinned to the same rustc as rust-toolchain.toml (and as pgxsinkit/electric-circuits)
# so the image build cannot drift from what CI and local builds produce. Upstream
# floated this at `rust:1-bookworm`.
FROM rust:1.96.0-bookworm AS build
WORKDIR /app
# Copy only what the build needs (no target/, no npm/).
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Default features only (no `tier`/`telemetry`) — minimal image, matching the
# conformance matrix. To ship S3 tiering, add `--features tier` here AND
# `ca-certificates` to the runtime stage.
RUN cargo build --release --locked

# ---- runtime stage: distroless (glibc cc), no shell / package manager ----
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=build /app/target/release/durable-streams-server /usr/local/bin/durable-streams-server
# Protocol default port (PROTOCOL.md §13.1); override with `--port`.
EXPOSE 4437
ENTRYPOINT ["/usr/local/bin/durable-streams-server"]
# The WAL pilot intentionally keeps this listener on loopback. The access sidecar is the only
# external listener; the task definition supplies an explicit persistent --data-dir and store
# identity arguments.
