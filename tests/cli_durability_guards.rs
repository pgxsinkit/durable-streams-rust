//! Startup guards on the durability flags, driven through the real binary.
//!
//! These are CLI-contract tests, not unit tests: the thing being protected is what an operator
//! typed, so the assertion has to be on the process the operator actually starts. `main()` exits
//! before the runtime or the store is built, so the refusal cases cost a process spawn and no I/O.

use std::process::{Child, Command, Stdio};
use std::{
    io::{Read, Write},
    net::TcpStream,
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
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
    assert!(
        ready.contains("\"contract_version\":\"durable-streams-store-ready-v1\""),
        "{ready}"
    );
    assert!(ready.contains(DIGEST), "{ready}");
    assert!(ready.contains("\"status\":\"ready\""), "{ready}");
    let reserved = http_response(14977, "PUT /_admin/a-user-stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    assert!(reserved.starts_with("HTTP/1.1 405"), "{reserved}");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The guard is wal-only. Memory mode makes no durability claim, so a defaulted temp data dir is
/// coherent there and must keep working — this is the path every lane and the `memory`
/// conformance configuration take.
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
