//! Startup guards on the durability flags, driven through the real binary.
//!
//! These are CLI-contract tests, not unit tests: the thing being protected is what an operator
//! typed, so the assertion has to be on the process the operator actually starts. `main()` exits
//! before the runtime or the store is built, so the refusal cases cost a process spawn and no I/O.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};

fn server() -> Command {
    Command::new(env!("CARGO_BIN_EXE_durable-streams-server"))
}

/// Reserve an ephemeral port by binding it and reading the assignment back. The
/// listener is dropped immediately, so this is a hint rather than a guarantee —
/// but it beats hard-coding ports into a suite that runs its cases in parallel
/// and leaves the previous run's sockets in TIME_WAIT.
fn unused_local_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("reserve test port")
        .local_addr()
        .unwrap()
        .port()
}

/// Block until `port` accepts a connection, i.e. the server got past every
/// startup guard and is serving. Panics at the deadline rather than letting a
/// later assertion fail for the wrong reason.
fn wait_until_listening(port: u16) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(_) => return,
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25))
            }
            Err(error) => panic!("server never listened on {port}: {error}"),
        }
    }
}

/// A spawned server and the data directory it owns, reaped in `Drop`.
///
/// Cleanup cannot live in a tail after the assertions: that tail runs only when
/// every assertion passed, which is the run where it matters least. A panicking
/// assertion would otherwise leak a process holding the data-dir lock and its
/// port, breaking every later test and rerun.
struct ServerUnderTest {
    child: Child,
    dir: std::path::PathBuf,
}

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Reap it: a killed-but-unwaited child stays a zombie, and on a
        // panicking unwind nothing else will collect it.
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Spawn and give the process a bounded chance to exit on its own. `Some(code)` = it refused
/// (and is reaped); `None` = it was still running at the deadline, which for these tests means
/// it got past the startup guards. Kills the child either way.
///
/// The second element is whatever the child wrote to stderr, for the cases that assert on the
/// refusal message; it is empty unless the caller piped stderr. Draining the pipe only after the
/// bounded wait (or the kill) is what keeps this bounded: reading to EOF first would block for as
/// long as the child stays alive, which is exactly the regression these tests have to catch.
fn exit_code_within(mut child: Child, budget: std::time::Duration) -> (Option<i32>, String) {
    let deadline = std::time::Instant::now() + budget;
    let code = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break Some(status.code().unwrap_or(-1)),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    };
    let mut stderr = Vec::new();
    if let Some(pipe) = child.stderr.as_mut() {
        let _ = pipe.read_to_end(&mut stderr);
    }
    (code, String::from_utf8_lossy(&stderr).into_owned())
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
    std::fs::create_dir_all(&dir).expect("mkdir");

    let child = server()
        .args(["--durability", "wal", "--port", "14972", "--data-dir"])
        .arg(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    assert_eq!(
        exit_code_within(child, std::time::Duration::from_secs(5)).0,
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
        exit_code_within(child, std::time::Duration::from_secs(5)).0,
        None,
        "memory mode must not be caught by the wal data-dir guard"
    );
}

/// A data directory belongs to exactly one process. Memory mode is the case
/// worth pinning, because it is the one that looks like it should be exempt:
/// it opens no WAL, but it still writes the stream files and their meta
/// sidecars under `--data-dir`, so a second process on the same directory
/// corrupts the first's state just as surely.
#[test]
fn a_second_server_on_the_same_data_dir_is_refused() {
    let dir =
        std::env::temp_dir().join(format!("ds-rust-cli-data-dir-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let owner_port = unused_local_port();
    let owner = ServerUnderTest {
        child: server()
            .args(["--durability", "memory", "--port"])
            .arg(owner_port.to_string())
            .arg("--data-dir")
            .arg(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn owner"),
        dir: dir.clone(),
    };
    // The lock is taken during startup, so the contention assertion is only
    // meaningful once the first server is actually up.
    wait_until_listening(owner_port);

    // Spawned with a bounded wait rather than `output()`: if the lock regresses, the second
    // server starts and serves forever, and `output()` would block on its stderr until the CI
    // job timeout. The regression has to read as a failed assertion, not as a hung job.
    let second = server()
        .args(["--durability", "memory", "--port"])
        .arg(unused_local_port().to_string())
        .arg("--data-dir")
        .arg(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn second");

    let (code, stderr) = exit_code_within(second, std::time::Duration::from_secs(10));
    assert_eq!(
        code,
        Some(2),
        "a second server on a locked data dir must exit 2 (None = it was still running, i.e. the \
         lock did not hold); stderr: {stderr}"
    );
    assert!(
        stderr.contains("already locked"),
        "the refusal must say the directory is locked; got: {stderr}"
    );
    drop(owner);
}
