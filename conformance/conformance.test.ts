/**
 * Run the server conformance suite against the Rust server.
 *
 * Two modes:
 *   - CI / default: builds nothing, but spawns the release binary
 *     (packages/durable-streams-rust/target/release/durable-streams-server) itself,
 *     mirroring the Caddy harness. Run with: `pnpm vitest run --project server-rust`
 *     (build the binary first with `cargo build --release`).
 *   - Manual: set RUST_SERVER_URL to point at an already-running server, e.g.
 *     RUST_SERVER_URL=http://localhost:4562 vitest run \
 *       --config packages/durable-streams-rust/conformance/vitest.config.ts
 */
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import * as path from 'node:path'
import { afterAll, beforeAll, describe } from 'vitest'
import { runConformanceTests } from '@durable-streams/server-conformance-tests'
import type { ChildProcess } from 'node:child_process'

// Manual mode: run against an externally-started server. Otherwise spawn our own.
const externalUrl = process.env.RUST_SERVER_URL
const port = Number(process.env.RUST_SERVER_PORT ?? 4562)
const longPollTimeoutMs = 500
const storeId = `2bc96d0b-9740-4f50-97c6-754b2b27d6b0`
const storeGeneration = `ff8b5fa6-e786-4994-8da0-f14e9e79f318`
const filesystemUuid = `253f14d5-cbee-4df8-9e3c-e44c6e41501b`
const artifactDigest = `sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`

const config = {
  baseUrl: externalUrl ?? `http://localhost:${port}`,
  longPollTimeoutMs,
  subscriptions: true,
}

let server: ChildProcess | null = null

beforeAll(async () => {
  if (!externalUrl) {
    const binary = resolveServerBinary()
    const dataDir = mkdtempSync(path.join(tmpdir(), `ds-rust-conformance-`))
    // Extra server flags for the run-configuration matrix (CI runs the suite
    // once per config — see README "Run-configuration matrix" + ci.yml). E.g.
    // RUST_SERVER_ARGS="--durability memory" or "--read-offload always" or
    // "--tail-cache-bytes 65536". Whitespace-separated; empty = the default
    // (wal, resident cache off on Linux).
    const extraArgs = (process.env.RUST_SERVER_ARGS ?? ``)
      .trim()
      .split(/\s+/)
      .filter(Boolean)
    const memoryMode = extraArgs.some(
      (arg, index) => arg === `--durability` && extraArgs[index + 1] === `memory`
    )
    const walArgs = memoryMode
      ? []
      : [
          `--store-id`,
          storeId,
          `--store-generation`,
          storeGeneration,
          `--protocol-version`,
          `1`,
          `--layout-version`,
          `1`,
          `--filesystem-uuid`,
          filesystemUuid,
          `--artifact-digest`,
          artifactDigest,
          `--wal-shards`,
          `1`,
          `--stream-lanes`,
          `1`,
        ]
    if (!memoryMode) {
      const bootstrap = spawnSync(
        binary,
        [
          `bootstrap-store`,
          `--data-dir`,
          dataDir,
          `--store-id`,
          storeId,
          `--store-generation`,
          storeGeneration,
          `--protocol-version`,
          `1`,
          `--layout-version`,
          `1`,
          `--durability-mode`,
          `wal`,
          `--wal-shards`,
          `1`,
          `--stream-lanes`,
          `1`,
          `--filesystem-uuid`,
          filesystemUuid,
          `--creation-time`,
          `2026-08-28T00:00:00Z`,
        ],
        { encoding: `utf8` }
      )
      if (bootstrap.status !== 0) {
        throw new Error(
          `Could not bootstrap conformance store: ${bootstrap.stderr}`
        )
      }
    }
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
        ...walArgs,
        ...extraArgs,
      ],
      {
        stdio: [`ignore`, `pipe`, `pipe`],
        env: {
          ...process.env,
          // Webhook callback/JWKS URLs must come from trusted operator
          // configuration, never from the request Host header.
          DS_PUBLIC_BASE_URL:
            process.env.DS_PUBLIC_BASE_URL ?? `http://localhost:${port}`,
        },
      }
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
})

function resolveServerBinary(): string {
  if (process.env.RUST_SERVER_BIN) return process.env.RUST_SERVER_BIN
  const metadata = JSON.parse(
    execFileSync(`cargo`, [`metadata`, `--format-version=1`, `--no-deps`], {
      cwd: path.join(__dirname, `..`),
      encoding: `utf8`,
    })
  ) as { target_directory: string }
  return path.join(metadata.target_directory, `release`, `durable-streams-server`)
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
