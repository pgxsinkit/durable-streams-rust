/**
 * Run the server conformance suite against the Rust server.
 *
 * Two modes:
 *   - CI / default: builds nothing, but spawns the release binary itself,
 *     mirroring the Caddy harness. Build it first with `cargo build --release`,
 *     then run `bun run test:conformance`. The binary is located through
 *     `cargo metadata` (honouring CARGO_TARGET_DIR and any workspace target
 *     directory); RUST_SERVER_BIN overrides it outright, which is what a CI job
 *     that downloads a prebuilt binary should use.
 *   - Manual: set RUST_SERVER_URL to point at an already-running server, e.g.
 *     RUST_SERVER_URL=http://localhost:4562 bun run test:conformance
 */
import { execFileSync, spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import * as path from 'node:path'
import { afterAll, beforeAll, describe } from 'vitest'
import { runConformanceTests } from '@durable-streams/server-conformance-tests'
import type { ChildProcess } from 'node:child_process'

// Manual mode: run against an externally-started server. Otherwise spawn our own.
const externalUrl = process.env.RUST_SERVER_URL
const port = Number(process.env.RUST_SERVER_PORT ?? 4562)
const longPollTimeoutMs = 500

const config = {
  baseUrl: externalUrl ?? `http://localhost:${port}`,
  longPollTimeoutMs,
  // This server implements the core protocol only; the subscription/control-plane
  // suite is out of scope, so skip it rather than report it as failing.
  subscriptions: false,
}

let server: ChildProcess | null = null
// Hoisted so afterAll can remove it: a full suite run leaves up to ~1 GB of
// stream data under this directory, and nothing else ever collects it.
let dataDir: string | null = null

beforeAll(async () => {
  if (!externalUrl) {
    const binary = resolveServerBinary()
    dataDir = mkdtempSync(path.join(tmpdir(), `ds-rust-conformance-`))
    // Extra server flags for the run-configuration matrix (CI runs the suite
    // once per config — see README "Run-configuration matrix" + ci.yml). E.g.
    // RUST_SERVER_ARGS="--durability memory" or "--read-offload always" or
    // "--tail-cache-bytes 65536". Whitespace-separated; empty = the default
    // (wal, resident cache off on Linux).
    const extraArgs = (process.env.RUST_SERVER_ARGS ?? ``)
      .trim()
      .split(/\s+/)
      .filter(Boolean)
    server = spawn(
      binary,
      [
        `--port`,
        String(port),
        `--data-dir`,
        dataDir,
        // Must match config.longPollTimeoutMs so the suite's timeout assertions hold.
        `--long-poll-timeout-ms`,
        String(longPollTimeoutMs),
        ...extraArgs,
      ],
      { stdio: [`ignore`, `pipe`, `pipe`] }
    )
    server.stderr?.on(`data`, (d: Buffer) =>
      process.stderr.write(`[rust] ${d}`)
    )
    server.on(`exit`, (code) => {
      if (code) process.stderr.write(`[rust] server exited with code ${code}\n`)
    })
  }
  await waitForServer(config.baseUrl, 15000)
}, 20000)

afterAll(async () => {
  if (server) {
    server.kill(`SIGTERM`)
    await new Promise((resolve) => setTimeout(resolve, 300))
  }
  // Only the directory this harness created: in manual mode the data dir
  // belongs to the server the operator started, and is not ours to delete.
  // Removal waits until after the grace period above, so the server has
  // released the data-dir lock and finished its last writes.
  if (dataDir) {
    rmSync(dataDir, { recursive: true, force: true })
    dataDir = null
  }
})

function resolveServerBinary(): string {
  if (process.env.RUST_SERVER_BIN) return process.env.RUST_SERVER_BIN
  const metadata = JSON.parse(
    execFileSync(`cargo`, [`metadata`, `--format-version=1`, `--no-deps`], {
      cwd: path.join(__dirname, `..`),
      encoding: `utf8`,
    })
  ) as { target_directory: string }
  return path.join(
    metadata.target_directory,
    `release`,
    `durable-streams-server`
  )
}

describe(`Rust Server Implementation`, () => {
  runConformanceTests(config)
})

async function waitForServer(
  baseUrl: string,
  timeoutMs: number
): Promise<void> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    try {
      // Any HTTP response (a 404 on `/` included) means the listener is up.
      await fetch(baseUrl)
      return
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
  }
  throw new Error(`Rust server did not become ready within ${timeoutMs}ms`)
}
