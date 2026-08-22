//! Startup guards on the durability flags, driven through the real binary.
//!
//! These are CLI-contract tests, not unit tests: the thing being protected is what an operator
//! typed, so the assertion has to be on the process the operator actually starts. `main()` exits
//! before the runtime or the store is built, so the refusal cases cost a process spawn and no I/O.

use std::process::{Child, Command, Stdio};

fn server() -> Command {
    Command::new(env!("CARGO_BIN_EXE_durable-streams-server"))
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

    assert_eq!(out.status.code(), Some(2), "wal with a defaulted --data-dir must exit 2");
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
    std::fs::create_dir_all(&dir).expect("mkdir");

    let child = server()
        .args(["--durability", "wal", "--port", "14972", "--data-dir"])
        .arg(&dir)
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
