use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use serde::Serialize;

use crate::store_manifest::StoreManifestV1;
use crate::wal::walset::WalSet;

const STARTING: u8 = 0;
const RECOVERING: u8 = 1;
const READY: u8 = 2;
const STOPPING: u8 = 3;

pub struct AdminReadiness {
    manifest: StoreManifestV1,
    artifact_digest: String,
    minimum_free_bytes: u64,
    minimum_free_inodes: u64,
    status: AtomicU8,
    wal: std::sync::OnceLock<Arc<WalSet>>,
}

#[derive(Serialize)]
struct ReadyResponse<'a> {
    contract_version: &'static str,
    status: &'static str,
    artifact_digest: &'a str,
    manifest: &'a StoreManifestV1,
    recovery: Recovery,
    reserve: Reserve,
    /// Effective `--max-chunk-bytes`: the per-response page *target* the read
    /// path aims for (PROTOCOL.md §5.6). Always present, `0` when reads are
    /// uncapped. Not on its own an upper bound on the response — see
    /// `max_value_bytes`.
    max_chunk_bytes: u64,
    /// The largest single message the store accepts, and therefore the largest
    /// it can be required to emit whole: a JSON page cuts only on a top-level
    /// value boundary, so one value larger than the page target is framed whole
    /// rather than split into malformed halves. A response body is at most
    /// `max(max_chunk_bytes, max_value_bytes)` plus framing (the 2-byte `[`/`]`
    /// array wrapper on a JSON stream, nothing on a byte stream). `0` would mean
    /// unbounded. Byte streams cut at any byte, so the page target alone bounds
    /// them.
    max_value_bytes: u64,
}
#[derive(Serialize)]
struct Recovery {
    completed: bool,
    wal_shards: Vec<WalShard>,
}
#[derive(Serialize)]
struct WalShard {
    shard: u32,
    durable_lsn: u64,
    checkpoint_lsn: u64,
}
#[derive(Serialize)]
struct Reserve {
    free_bytes: u64,
    free_inodes: u64,
    minimum_free_bytes: u64,
    minimum_free_inodes: u64,
    satisfied: bool,
}

impl AdminReadiness {
    pub fn new(
        manifest: StoreManifestV1,
        artifact_digest: String,
        minimum_free_bytes: u64,
        minimum_free_inodes: u64,
    ) -> Self {
        Self {
            manifest,
            artifact_digest,
            minimum_free_bytes,
            minimum_free_inodes,
            status: AtomicU8::new(STARTING),
            wal: std::sync::OnceLock::new(),
        }
    }
    pub fn attach_wal(&self, wal: Arc<WalSet>) {
        let _ = self.wal.set(wal);
    }
    pub fn recovering(&self) {
        self.status.store(RECOVERING, Ordering::Release);
    }
    pub fn ready(&self) {
        self.status.store(READY, Ordering::Release);
    }
    pub fn stopping(&self) {
        self.status.store(STOPPING, Ordering::Release);
    }
    pub fn json(&self, data_dir: &std::path::Path) -> (u16, Vec<u8>) {
        let status = self.status.load(Ordering::Acquire);
        let (free_bytes, free_inodes) = filesystem_free(data_dir).unwrap_or((0, 0));
        let reserve_ok =
            free_bytes >= self.minimum_free_bytes && free_inodes >= self.minimum_free_inodes;
        let state = match status {
            STARTING => "starting",
            RECOVERING => "recovering",
            // Storage pressure is not a ready state even though replay itself
            // completed. Keep it non-ready until the configured reserve returns.
            READY if !reserve_ok => "starting",
            READY => "ready",
            _ => "stopping",
        };
        let completed = status == READY;
        let wal_shards = self
            .wal
            .get()
            .map(|w| {
                w.shards()
                    .iter()
                    .enumerate()
                    .map(|(i, shard)| WalShard {
                        shard: i as u32,
                        durable_lsn: shard.durable_lsn_now(),
                        checkpoint_lsn: shard.read_checkpoint_lsn(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let body = serde_json::to_vec(&ReadyResponse {
            contract_version: "durable-streams-store-ready-v1",
            status: state,
            artifact_digest: &self.artifact_digest,
            manifest: &self.manifest,
            recovery: Recovery {
                completed,
                wal_shards,
            },
            reserve: Reserve {
                free_bytes,
                free_inodes,
                minimum_free_bytes: self.minimum_free_bytes,
                minimum_free_inodes: self.minimum_free_inodes,
                satisfied: reserve_ok,
            },
            max_chunk_bytes: crate::handlers::max_chunk_bytes(),
            max_value_bytes: crate::api::MAX_BODY_BYTES as u64,
        })
        .expect("ready response serializes");
        (if completed && reserve_ok { 200 } else { 503 }, body)
    }
}

fn filesystem_free(path: &std::path::Path) -> std::io::Result<(u64, u64)> {
    #[cfg(test)]
    if let Some(value) = *TEST_FILESYSTEM_FREE.lock().unwrap() {
        return Ok(value);
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in data dir")
        })?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((
            (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64),
            stat.f_favail as u64,
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok((0, 0))
    }
}

#[cfg(test)]
static TEST_FILESYSTEM_FREE: std::sync::Mutex<Option<(u64, u64)>> = std::sync::Mutex::new(None);

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> StoreManifestV1 {
        StoreManifestV1 {
            store_id: "2bc96d0b-9740-4f50-97c6-754b2b27d6b0".into(),
            store_generation: "ff8b5fa6-e786-4994-8da0-f14e9e79f318".into(),
            protocol_version: 1,
            layout_version: 1,
            durability_mode: "wal".into(),
            wal_shard_count: 1,
            stream_lane_count: 1,
            filesystem_uuid: "253f14d5-cbee-4df8-9e3c-e44c6e41501b".into(),
            creation_time: "2026-08-27T19:00:00Z".into(),
        }
    }
    /// The readiness document is how a client learns the store's read page
    /// budget before its first read. `--max-chunk-bytes` is what the read path
    /// applies, so that is the number readiness must publish.
    #[test]
    fn readiness_advertises_the_configured_read_chunk_cap() {
        let _settings =
            crate::handlers::test_support::DurabilityGuard::memory_with_max_chunk(65_536);
        let readiness = AdminReadiness::new(
            manifest(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            0,
            0,
        );
        readiness.ready();
        let (_, body) = readiness.json(std::path::Path::new("."));
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["max_chunk_bytes"], 65_536);
    }

    /// `--max-chunk-bytes 0` (unlimited) must be advertised as `0`, not by
    /// omitting the field: a client cannot distinguish an absent field from an
    /// older store that does not publish one, so the field is always present.
    #[test]
    fn uncapped_reads_are_advertised_as_zero_rather_than_omitted() {
        let _settings = crate::handlers::test_support::DurabilityGuard::memory_with_max_chunk(0);
        let readiness = AdminReadiness::new(
            manifest(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            0,
            0,
        );
        readiness.ready();
        let (_, body) = readiness.json(std::path::Path::new("."));
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            body.as_object().unwrap().contains_key("max_chunk_bytes"),
            "an uncapped store must still publish the field: {body}"
        );
        assert_eq!(body["max_chunk_bytes"], 0);
    }

    /// `max_chunk_bytes` is a page *target*, not a hard response bound: a JSON
    /// stream cuts only on a top-level value boundary, so a single value larger
    /// than the cap is served whole (there is no smaller well-formed page). A
    /// consumer sizing a body limit needs the other half of that bound — the
    /// largest single message the store will accept.
    #[test]
    fn readiness_advertises_the_single_value_bound_beside_the_page_cap() {
        let _settings = crate::handlers::test_support::DurabilityGuard::memory_with_max_chunk(128);
        let readiness = AdminReadiness::new(
            manifest(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            0,
            0,
        );
        readiness.ready();
        let (_, body) = readiness.json(std::path::Path::new("."));
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["max_chunk_bytes"], 128);
        assert_eq!(
            body["max_value_bytes"],
            crate::api::MAX_BODY_BYTES as u64,
            "the value bound is the largest append the store accepts: {body}"
        );
    }

    #[test]
    fn reserve_failed_readiness_is_503_and_never_ready() {
        *TEST_FILESYSTEM_FREE.lock().unwrap() = Some((1, 1));
        let readiness = AdminReadiness::new(
            manifest(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            2,
            2,
        );
        readiness.ready();
        let (status, body) = readiness.json(std::path::Path::new("."));
        *TEST_FILESYSTEM_FREE.lock().unwrap() = None;
        assert_eq!(status, 503);
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "starting");
        assert_eq!(body["recovery"]["completed"], true);
        assert_eq!(body["reserve"]["satisfied"], false);
    }
}
