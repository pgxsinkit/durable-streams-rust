//! Store identity manifest.  This file is deliberately strict: it is the
//! observed, on-volume half of the deployment identity contract.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

pub const MANIFEST_FILE: &str = ".durable-streams-store-v1.json";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoreManifestV1 {
    pub store_id: String,
    pub store_generation: String,
    pub protocol_version: u32,
    pub layout_version: u32,
    pub durability_mode: String,
    pub wal_shard_count: u32,
    pub stream_lane_count: u32,
    pub filesystem_uuid: String,
    pub creation_time: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedStoreIdentityV1 {
    pub store_id: String,
    pub store_generation: String,
    pub protocol_version: u32,
    pub layout_version: u32,
    pub durability_mode: String,
    pub wal_shard_count: u32,
    pub stream_lane_count: u32,
    pub filesystem_uuid: String,
}

impl StoreManifestV1 {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(MANIFEST_FILE)
    }

    pub fn validate(&self) -> Result<(), String> {
        canonical_uuid("store_id", &self.store_id)?;
        canonical_uuid("store_generation", &self.store_generation)?;
        canonical_uuid("filesystem_uuid", &self.filesystem_uuid)?;
        if self.protocol_version == 0 || self.layout_version == 0 {
            return Err("protocol_version and layout_version must be positive".into());
        }
        if self.durability_mode != "wal" {
            return Err("durability_mode must be exactly \"wal\"".into());
        }
        if self.wal_shard_count == 0 || self.stream_lane_count == 0 {
            return Err("wal_shard_count and stream_lane_count must be positive".into());
        }
        canonical_time(&self.creation_time)
    }

    pub fn compare_expected(&self, expected: &ExpectedStoreIdentityV1) -> Result<(), String> {
        let checks = [
            ("store_id", &self.store_id, &expected.store_id),
            (
                "store_generation",
                &self.store_generation,
                &expected.store_generation,
            ),
            (
                "durability_mode",
                &self.durability_mode,
                &expected.durability_mode,
            ),
            (
                "filesystem_uuid",
                &self.filesystem_uuid,
                &expected.filesystem_uuid,
            ),
        ];
        for (name, observed, wanted) in checks {
            if observed != wanted {
                return Err(format!(
                    "manifest {name} mismatch: expected {wanted:?}, observed {observed:?}"
                ));
            }
        }
        let numbers = [
            (
                "protocol_version",
                self.protocol_version as u64,
                expected.protocol_version as u64,
            ),
            (
                "layout_version",
                self.layout_version as u64,
                expected.layout_version as u64,
            ),
            (
                "wal_shard_count",
                self.wal_shard_count as u64,
                expected.wal_shard_count as u64,
            ),
            (
                "stream_lane_count",
                self.stream_lane_count as u64,
                expected.stream_lane_count as u64,
            ),
        ];
        for (name, observed, wanted) in numbers {
            if observed != wanted {
                return Err(format!(
                    "manifest {name} mismatch: expected {wanted}, observed {observed}"
                ));
            }
        }
        Ok(())
    }
}

pub fn read(data_dir: &Path) -> Result<StoreManifestV1, String> {
    let path = StoreManifestV1::path(data_dir);
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read store manifest {}: {e}", path.display()))?;
    reject_duplicate_keys(&raw)?;
    let manifest: StoreManifestV1 = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid store manifest {}: {e}", path.display()))?;
    manifest.validate()?;
    Ok(manifest)
}

/// Create only on a pristine data dir (other than the process lock).
pub fn create_atomically(data_dir: &Path, manifest: &StoreManifestV1) -> Result<(), String> {
    manifest.validate()?;
    let target = StoreManifestV1::path(data_dir);
    if target.exists() {
        return Err(format!(
            "store manifest already exists: {}",
            target.display()
        ));
    }
    let entries = std::fs::read_dir(data_dir)
        .map_err(|e| format!("cannot inspect {}: {e}", data_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_name() != ".durable-streams.lock" {
            return Err(format!(
                "bootstrap-store refuses non-empty data directory: found {}",
                entry.path().display()
            ));
        }
    }
    let encoded = serde_json::to_vec(manifest).map_err(|e| e.to_string())?;
    let temp = data_dir.join(format!(".{MANIFEST_FILE}.tmp-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|e| format!("cannot create temporary manifest: {e}"))?;
    if let Err(error) = (|| -> io::Result<()> {
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temp, &target)?;
        fsync_dir(data_dir)?;
        Ok(())
    })() {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("cannot atomically create store manifest: {error}"));
    }
    Ok(())
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

pub fn canonical_uuid(name: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
        return Err(format!("{name} must be a canonical lowercase UUID"));
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(i, c)| ![8, 13, 18, 23].contains(&i) && !matches!(*c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{name} must be a canonical lowercase UUID"));
    }
    Ok(())
}

pub fn canonical_time(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, c)| ![4, 7, 10, 13, 16, 19].contains(&i) && !c.is_ascii_digit())
    {
        return Err("creation_time must be canonical RFC3339 UTC (YYYY-MM-DDTHH:MM:SSZ)".into());
    }
    let n = |a: usize, b: usize| value[a..b].parse::<u32>().unwrap_or(u32::MAX);
    let (year, month, day, hour, minute, second) =
        (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err("creation_time is not a valid RFC3339 UTC timestamp".into());
    }
    Ok(())
}

/// Validate JSON syntax while rejecting a repeated object key at *any* nesting
/// level before serde's normal map decoding could silently keep the last value.
fn reject_duplicate_keys(input: &str) -> Result<(), String> {
    let mut de = serde_json::Deserializer::from_str(input);
    DuplicateCheck
        .deserialize(&mut de)
        .map_err(|e| format!("invalid JSON or duplicate key in store manifest: {e}"))?;
    de.end()
        .map_err(|e| format!("invalid trailing JSON in store manifest: {e}"))
}

struct DuplicateCheck;
impl<'de> DeserializeSeed<'de> for DuplicateCheck {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(DuplicateVisitor)
    }
}
struct DuplicateVisitor;
impl<'de> Visitor<'de> for DuplicateVisitor {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(DuplicateCheck)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
            }
            map.next_value_seed(DuplicateCheck)?;
        }
        Ok(())
    }
}

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
            wal_shard_count: 2,
            stream_lane_count: 1,
            filesystem_uuid: "253f14d5-cbee-4df8-9e3c-e44c6e41501b".into(),
            creation_time: "2026-08-27T19:00:00Z".into(),
        }
    }
    #[test]
    fn rejects_duplicate_keys() {
        let d = std::env::temp_dir().join(format!("ds-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            StoreManifestV1::path(&d),
            r#"{"store_id":"x","store_id":"x"}"#,
        )
        .unwrap();
        assert!(read(&d).unwrap_err().contains("duplicate"));
        let _ = std::fs::remove_dir_all(d);
    }
    #[test]
    fn validates_fixture() {
        manifest().validate().unwrap();
    }
    #[test]
    fn rejects_noncanonical_or_invalid_creation_times() {
        for value in [
            "2026-02-29T19:00:00Z",
            "2024-02-30T19:00:00Z",
            "2026-01-01t19:00:00Z",
            "2026-01-01T19:00:00+00:00",
            "2026-1-01T19:00:00Z",
            "2026-01-01T24:00:00Z",
        ] {
            assert!(canonical_time(value).is_err(), "{value}");
        }
        assert!(canonical_time("2024-02-29T23:59:59Z").is_ok());
    }
}
