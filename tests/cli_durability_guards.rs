//! Startup guards on the durability flags, driven through the real binary.
//!
//! These are CLI-contract tests, not unit tests: the thing being protected is what an operator
//! typed, so the assertion has to be on the process the operator actually starts. `main()` exits
//! before the runtime or the store is built, so the refusal cases cost a process spawn and no I/O.

use std::process::{Child, Command, Stdio};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

fn server() -> Command {
    Command::new(env!("CARGO_BIN_EXE_durable-streams-server"))
}

const STORE_ID: &str = "2bc96d0b-9740-4f50-97c6-754b2b27d6b0";
const STORE_GENERATION: &str = "ff8b5fa6-e786-4994-8da0-f14e9e79f318";
const FILESYSTEM_UUID: &str = "253f14d5-cbee-4df8-9e3c-e44c6e41501b";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn bootstrap(dir: &std::path::Path) {
    let out = server()
        .args(["bootstrap-store", "--data-dir"])
        .arg(dir)
        .args([
            "--store-id",
            STORE_ID,
            "--store-generation",
            STORE_GENERATION,
            "--protocol-version",
            "1",
            "--layout-version",
            "1",
            "--durability-mode",
            "wal",
            "--wal-shards",
            "1",
            "--stream-lanes",
            "1",
            "--filesystem-uuid",
            FILESYSTEM_UUID,
            "--creation-time",
            "2026-08-27T19:00:00Z",
        ])
        .output()
        .expect("bootstrap");
    assert!(
        out.status.success(),
        "bootstrap stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn wal_args(dir: &std::path::Path, port: &str) -> Vec<String> {
    [
        "--durability",
        "wal",
        "--data-dir",
        dir.to_str().unwrap(),
        "--port",
        port,
        "--store-id",
        STORE_ID,
        "--store-generation",
        STORE_GENERATION,
        "--protocol-version",
        "1",
        "--layout-version",
        "1",
        "--filesystem-uuid",
        FILESYSTEM_UUID,
        "--artifact-digest",
        DIGEST,
        "--wal-shards",
        "1",
        "--stream-lanes",
        "1",
        "--minimum-free-bytes",
        "21474836480",
        "--minimum-free-inodes",
        "10000",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect()
}

fn replace_arg(args: &mut [String], flag: &str, value: &str) {
    let index = args
        .iter()
        .position(|argument| argument == flag)
        .expect("flag present");
    args[index + 1] = value.to_string();
}

fn http_response(port: u16, request: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut stream) => {
                stream.write_all(request.as_bytes()).expect("write request");
                let mut response = String::new();
                stream.read_to_string(&mut response).expect("read response");
                return response;
            }
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25))
            }
            Err(error) => panic!("server did not listen: {error}"),
        }
    }
}

fn unused_local_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("reserve test port")
        .local_addr()
        .unwrap()
        .port()
}

/// Spawn and give the process a bounded chance to exit on its own. `Some(code)` = it refused
/// (and is reaped); `None` = it was still running at the deadline, which for these tests means
/// it got past the startup guards. Kills the child either way.
fn exit_code_within(mut child: Child, budget: std::time::Duration) -> Option<i32> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return Some(status.code().unwrap_or(-1)),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }
}

/// The guard this file exists for: wal durability into the DEFAULT data dir is a temp dir, so
/// every append would be fsynced and discarded on restart with nothing to show for it. Refuse.
#[test]
fn wal_without_an_explicit_data_dir_refuses_to_start() {
    let out = server()
        .args(["--durability", "wal", "--port", "14971"])
        .output()
        .expect("spawn");

    assert_eq!(
        out.status.code(),
        Some(2),
        "wal with a defaulted --data-dir must exit 2"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--data-dir"),
        "the refusal must name the flag that fixes it; got: {stderr}"
    );
}

/// The gate is whether `--data-dir` was NAMED, not whether the path looks durable — a throwaway
/// directory stays available to tests and benches that want the wal code path without
/// persistence. (The conformance harness relies on exactly this: it passes an explicit mkdtemp.)
#[test]
fn wal_with_an_explicit_data_dir_starts_even_under_tmp() {
    let dir = std::env::temp_dir().join("ds-rust-cli-guard-wal-explicit");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);

    let child = server()
        .args(wal_args(&dir, "14972"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    assert_eq!(
        exit_code_within(child, std::time::Duration::from_secs(5)),
        None,
        "an explicit --data-dir must satisfy the guard, even pointing at a temp path"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ordinary_wal_startup_refuses_a_blank_directory_without_initializing_it() {
    let dir = std::env::temp_dir().join("ds-rust-cli-blank-store");
    let _ = std::fs::remove_dir_all(&dir);
    let out = server()
        .args(wal_args(&dir, "14974"))
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        entries,
        vec![std::ffi::OsString::from(".durable-streams.lock")]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wal_identity_mismatches_refuse_before_store_or_wal_mutation() {
    let dir = std::env::temp_dir().join("ds-rust-cli-identity-mismatch");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    for (flag, value) in [
        ("--store-id", "3bc96d0b-9740-4f50-97c6-754b2b27d6b0"),
        ("--store-generation", "ef8b5fa6-e786-4994-8da0-f14e9e79f318"),
        ("--protocol-version", "2"),
        ("--layout-version", "2"),
        ("--filesystem-uuid", "353f14d5-cbee-4df8-9e3c-e44c6e41501b"),
        ("--wal-shards", "2"),
        ("--stream-lanes", "2"),
    ] {
        let mut args = wal_args(&dir, "14978");
        replace_arg(&mut args, flag, value);
        let out = server().args(args).output().expect("mismatched startup");
        assert_eq!(out.status.code(), Some(2), "{flag}");
        assert!(!dir.join("wal").exists(), "{flag} opened WAL");
        assert!(!dir.join("streams").exists(), "{flag} built stream store");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wal_reserve_floor_cannot_be_lowered() {
    let dir = std::env::temp_dir().join("ds-rust-cli-reserve-floor");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    let mut args = wal_args(&dir, "14979");
    replace_arg(&mut args, "--minimum-free-bytes", "0");
    let out = server().args(args).output().expect("startup");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("reserve"));
    assert!(!dir.join("wal").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn expiry_reaper_cli_rejects_invalid_mode_and_unbounded_controls() {
    for (flag, value, expected) in [
        (
            "--expiry-reaper-mode",
            "eager",
            "--expiry-reaper-mode must be off|observe|delete",
        ),
        (
            "--expiry-scan-rate",
            "0",
            "--expiry-scan-rate must be at least 1",
        ),
        (
            "--expiry-delete-rate",
            "0",
            "--expiry-delete-rate must be at least 1",
        ),
        (
            "--expiry-delete-concurrency",
            "0",
            "--expiry-delete-concurrency must be at least 1",
        ),
        (
            "--expiry-scan-rate",
            "1000001",
            "--expiry-scan-rate must be at most 1000000",
        ),
        (
            "--expiry-delete-rate",
            "100001",
            "--expiry-delete-rate must be at most 100000",
        ),
        (
            "--expiry-delete-concurrency",
            "1025",
            "--expiry-delete-concurrency must be at most 1024",
        ),
        (
            "--expiry-bulk-fraction",
            "1.1",
            "--expiry-bulk-fraction must be between 0 and 1",
        ),
        (
            "--expiry-clock-jump-seconds",
            "0",
            "--expiry-clock-jump-seconds must be at least 1",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let out = server()
            .args([
                "--durability",
                "memory",
                "--data-dir",
                dir.path().to_str().unwrap(),
                flag,
                value,
            ])
            .output()
            .expect("expiry option validation");
        assert_eq!(out.status.code(), Some(2), "{flag}={value}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(expected),
            "{flag}={value} should report {expected:?}; got {stderr:?}"
        );
    }
}

#[test]
fn proactive_expiry_reaping_rejects_s3_tiering() {
    let dir = std::env::temp_dir().join("ds-rust-expiry-tier-guard");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    let mut args = wal_args(&dir, "14983");
    args.extend(
        [
            "--expiry-reaper-mode",
            "delete",
            "--tier",
            "s3",
            "--tier-endpoint",
            "https://objects.example",
            "--tier-bucket",
            "test",
        ]
        .into_iter()
        .map(str::to_string),
    );
    let out = server().args(args).output().expect("tier guard");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--expiry-reaper-mode delete cannot be combined with --tier s3"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn delete_mode_reaps_an_expired_stream_without_a_request_to_that_path() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let port = unused_local_port();
    let port_text = port.to_string();
    let mut child = server()
        .args([
            "--durability",
            "memory",
            "--data-dir",
            dir.to_str().unwrap(),
            "--port",
            port_text.as_str(),
            "--expiry-reaper-mode",
            "delete",
            "--expiry-startup-grace-seconds",
            "0",
            "--expiry-scan-rate",
            "1000",
            "--expiry-delete-rate",
            "1000",
            "--expiry-delete-concurrency",
            "1",
            "--expiry-bulk-fraction",
            "1.0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server");

    let created = http_response(
        port,
        "PUT /expires-unobserved HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nStream-TTL: 1\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(created.starts_with("HTTP/1.1 201"), "{created}");

    let streams = dir.join("streams");
    let stream_artifact_count = || {
        std::fs::read_dir(&streams)
            .expect("streams directory")
            .filter_map(Result::ok)
            .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
            .count()
    };
    assert!(
        stream_artifact_count() >= 2,
        "data and metadata were created"
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while stream_artifact_count() != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let remaining = stream_artifact_count();

    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(remaining, 0, "expired stream artifacts were not reaped");
}

#[test]
fn bootstrap_refuses_every_preexisting_store_state_class() {
    for class in ["manifest", "wal", "streams", "segments", "cold"] {
        let dir = std::env::temp_dir().join(format!("ds-rust-bootstrap-refusal-{class}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        if class == "manifest" {
            bootstrap(&dir);
        } else {
            std::fs::create_dir(dir.join(class)).unwrap();
        }
        let out = server()
            .args(["bootstrap-store", "--data-dir"])
            .arg(&dir)
            .args([
                "--store-id",
                STORE_ID,
                "--store-generation",
                STORE_GENERATION,
                "--protocol-version",
                "1",
                "--layout-version",
                "1",
                "--durability-mode",
                "wal",
                "--wal-shards",
                "1",
                "--stream-lanes",
                "1",
                "--filesystem-uuid",
                FILESYSTEM_UUID,
                "--creation-time",
                "2026-08-27T19:00:00Z",
            ])
            .output()
            .expect("bootstrap refusal");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{class}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn acknowledged_append_survives_kill_and_real_cli_restart() {
    let dir = std::env::temp_dir().join("ds-rust-cli-ack-recovery");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    let mut first = server()
        .args(wal_args(&dir, "14980"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("first server");
    let created = http_response(14980, "PUT /recovery HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: 0\r\n\r\n");
    assert!(created.starts_with("HTTP/1.1 201"), "{created}");
    let appended = http_response(14980, "POST /recovery HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\n\r\nack");
    assert!(appended.starts_with("HTTP/1.1 204"), "{appended}");
    let _ = first.kill();
    let _ = first.wait();
    let mut second = server()
        .args(wal_args(&dir, "14981"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("restarted server");
    let recovered = http_response(
        14981,
        "GET /recovery HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
    assert!(recovered.ends_with("ack"), "{recovered}");
    let _ = second.kill();
    let _ = second.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_wal_server_is_refused_by_the_data_directory_lock() {
    let dir = std::env::temp_dir().join("ds-rust-cli-data-dir-lock");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    let first = server()
        .args(wal_args(&dir, "14975"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("first server");
    assert_eq!(
        exit_code_within(first, std::time::Duration::from_millis(250)),
        None
    );
    // The first child above was killed by the helper, so keep a real owner alive for the contention assertion.
    let owner = server()
        .args(wal_args(&dir, "14975"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("owner server");
    std::thread::sleep(std::time::Duration::from_millis(100));
    let second = server()
        .args(wal_args(&dir, "14976"))
        .output()
        .expect("second server");
    assert_eq!(
        second.status.code(),
        Some(2),
        "second stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let mut owner = owner;
    let _ = owner.kill();
    let _ = owner.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_memory_server_is_refused_by_the_data_directory_lock() {
    let dir = std::env::temp_dir().join("ds-rust-cli-memory-data-dir-lock");
    let _ = std::fs::remove_dir_all(&dir);
    let mut owner = server()
        .args([
            "--durability",
            "memory",
            "--data-dir",
            dir.to_str().unwrap(),
            "--port",
            "14982",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("owner server");
    let ready = http_response(
        14982,
        "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(ready.starts_with("HTTP/1.1 404"), "{ready}");

    let second = server()
        .args([
            "--durability",
            "memory",
            "--data-dir",
            dir.to_str().unwrap(),
            "--port",
            "14983",
        ])
        .output()
        .expect("second server");
    assert_eq!(
        second.status.code(),
        Some(2),
        "second stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let _ = owner.kill();
    let _ = owner.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn readiness_is_attested_and_admin_paths_are_reserved() {
    let dir = std::env::temp_dir().join("ds-rust-cli-readiness");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    let mut child = server()
        .args(wal_args(&dir, "14977"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server");
    let ready = http_response(
        14977,
        "GET /_admin/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        ready.starts_with("HTTP/1.1 200") || ready.starts_with("HTTP/1.1 503"),
        "{ready}"
    );
    assert!(
        ready.contains("\"contract_version\":\"durable-streams-store-ready-v1\""),
        "{ready}"
    );
    assert!(ready.contains(DIGEST), "{ready}");
    if ready.starts_with("HTTP/1.1 200") {
        assert!(ready.contains("\"status\":\"ready\""), "{ready}");
    } else {
        // Readiness is intentionally 503 when the test filesystem has less
        // than the production 20 GiB reserve. The attestation must still be
        // complete, recovery must have finished, and only the reserve check may
        // keep the server non-ready.
        assert!(ready.contains("\"status\":\"starting\""), "{ready}");
        assert!(
            ready.contains("\"recovery\":{\"completed\":true"),
            "{ready}"
        );
        assert!(ready.contains("\"satisfied\":false"), "{ready}");
    }
    let reserved = http_response(14977, "PUT /_admin/a-user-stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    assert!(reserved.starts_with("HTTP/1.1 405"), "{reserved}");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Readiness advertises a cap so a client can size its response buffer before
/// its first read; the number is only worth publishing if it is the same one
/// the read path applies. This drives both through the real process: what
/// `/_admin/ready` says, and where a read of a larger backlog actually stops.
#[test]
fn readiness_advertises_the_chunk_cap_reads_actually_apply() {
    const CAP: u64 = 128;
    let dir = std::env::temp_dir().join("ds-rust-cli-ready-chunk-cap");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    let port = unused_local_port();
    let mut args = wal_args(&dir, &port.to_string());
    args.push("--max-chunk-bytes".to_string());
    args.push(CAP.to_string());
    let mut child = server()
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server");

    let ready = http_response(
        port,
        "GET /_admin/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    // 200 or 503: a test filesystem under the production 20 GiB reserve is not
    // ready, but the document it serves must still be complete.
    assert!(
        ready.starts_with("HTTP/1.1 200") || ready.starts_with("HTTP/1.1 503"),
        "{ready}"
    );
    assert!(
        ready.contains(&format!("\"max_chunk_bytes\":{CAP}")),
        "readiness must publish the configured cap: {ready}"
    );

    let created = http_response(
        port,
        "PUT /capped HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(created.contains(" 201"), "create: {created}");
    let payload = "x".repeat(2000);
    let appended = http_response(
        port,
        &format!(
            "POST /capped HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert!(appended.contains(" 204"), "append: {appended}");
    let read = http_response(
        port,
        "GET /capped HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let page_end: u64 = read
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("stream-next-offset:")
                .map(|value| value.trim().to_string())
        })
        .unwrap_or_else(|| panic!("no Stream-Next-Offset in: {read}"))
        .rsplit('_')
        .next()
        .unwrap()
        .parse()
        .expect("numeric offset");
    assert_eq!(
        page_end, CAP,
        "the advertised cap must be the one the read path applies"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `max_chunk_bytes` is a page target, not a hard bound on the response. A JSON
/// stream cuts only on a top-level value boundary, so a single value larger than
/// the cap is framed whole — a consumer that treated the page cap as an upper
/// bound would reject a response the server is entitled to send. Readiness
/// therefore publishes the other half of the bound, and this pins both halves
/// against a server that actually overshoots.
#[test]
fn an_oversize_value_is_served_whole_and_readiness_bounds_it() {
    const CAP: u64 = 128;
    /// `crate::api::MAX_BODY_BYTES`, the largest request body the server accepts
    /// and therefore the largest single message it can be made to emit whole.
    const VALUE_BOUND: u64 = 1024 * 1024 * 1024;
    let dir = std::env::temp_dir().join("ds-rust-cli-oversize-value");
    let _ = std::fs::remove_dir_all(&dir);
    bootstrap(&dir);
    let port = unused_local_port();
    let mut args = wal_args(&dir, &port.to_string());
    args.push("--max-chunk-bytes".to_string());
    args.push(CAP.to_string());
    let mut child = server()
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server");

    let ready = http_response(
        port,
        "GET /_admin/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        ready.contains(&format!("\"max_chunk_bytes\":{CAP}")),
        "readiness must publish the nominal page cap: {ready}"
    );
    assert!(
        ready.contains(&format!("\"max_value_bytes\":{VALUE_BOUND}")),
        "readiness must publish the single-value bound: {ready}"
    );

    let created = http_response(
        port,
        "PUT /oversize HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(created.contains(" 201"), "create: {created}");
    // One JSON value, comfortably larger than the cap: there is no well-formed
    // page smaller than the whole value.
    let value = format!("{{\"m\":\"{}\"}}", "x".repeat(500));
    assert!(value.len() as u64 > CAP);
    let appended = http_response(
        port,
        &format!(
            "POST /oversize HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{value}",
            value.len()
        ),
    );
    assert!(appended.contains(" 204"), "append: {appended}");

    let read = http_response(
        port,
        "GET /oversize HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let body = read
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_else(|| panic!("no body in: {read}"));
    assert_eq!(
        body,
        format!("[{value}]"),
        "the oversize value must be framed whole, not split"
    );
    assert!(
        body.len() as u64 > CAP,
        "this test is only meaningful if the response overshoots the cap"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The explicit-data-dir guard is wal-only. Memory mode makes no WAL durability claim, so a
/// defaulted temp data dir remains coherent; it is still lifetime-locked once selected.
#[test]
fn memory_without_an_explicit_data_dir_still_starts() {
    let child = server()
        .args(["--durability", "memory", "--port", "14973"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    assert_eq!(
        exit_code_within(child, std::time::Duration::from_secs(5)),
        None,
        "memory mode must not be caught by the wal data-dir guard"
    );
}
