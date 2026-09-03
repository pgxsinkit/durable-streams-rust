//! CLI/environment contract for `--max-chunk-bytes` (PROTOCOL.md §5.6).
//!
//! Like `cli_durability_guards.rs`, these are contract tests on the process an
//! operator actually starts: the thing being protected is a configuration
//! decision (which source wins, and what an unusable value does), and neither is
//! observable from inside the library.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};

fn server() -> Command {
    Command::new(env!("CARGO_BIN_EXE_durable-streams-server"))
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ds-max-chunk-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create data dir");
    dir
}

fn unused_local_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("reserve test port")
        .local_addr()
        .unwrap()
        .port()
}

fn http_response(port: u16, request: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut stream) => {
                stream.write_all(request.as_bytes()).expect("write request");
                let mut response = Vec::new();
                stream.read_to_end(&mut response).expect("read response");
                return String::from_utf8_lossy(&response).into_owned();
            }
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25))
            }
            Err(error) => panic!("server did not listen: {error}"),
        }
    }
}

/// Start a memory-mode server, append `payload_len` bytes to one stream, and
/// return the `Stream-Next-Offset` byte position of a read from offset 0 — i.e.
/// the chunk size the running configuration actually applied.
fn first_page_end(child: &mut Child, port: u16, payload_len: usize) -> u64 {
    let created = http_response(
        port,
        "PUT /chunked HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(created.contains(" 201"), "create: {created}");
    let payload = "x".repeat(payload_len);
    let appended = http_response(
        port,
        &format!(
            "POST /chunked HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        ),
    );
    assert!(appended.contains(" 204"), "append: {appended}");
    let read = http_response(
        port,
        "GET /chunked HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let _ = child.kill();
    let _ = child.wait();
    let offset = read
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("stream-next-offset:")
                .map(|value| value.trim().to_string())
        })
        .unwrap_or_else(|| panic!("no Stream-Next-Offset in: {read}"));
    offset
        .rsplit('_')
        .next()
        .unwrap()
        .parse()
        .expect("numeric offset")
}

/// The environment fallback configures the cap when no flag is given.
#[test]
fn env_fallback_caps_reads() {
    let dir = tmp_dir("env");
    let port = unused_local_port();
    let mut child = server()
        .args(["--durability", "memory", "--port"])
        .arg(port.to_string())
        .arg("--data-dir")
        .arg(&dir)
        .env("DS_MAX_CHUNK_BYTES", "64")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    assert_eq!(first_page_end(&mut child, port, 2000), 64);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A flag and the environment fallback both present: the flag wins. The two
/// values are distinct and both smaller than the payload, so the response says
/// which source was used.
#[test]
fn flag_overrides_the_environment_fallback() {
    let dir = tmp_dir("flag-wins");
    let port = unused_local_port();
    let mut child = server()
        .args([
            "--durability",
            "memory",
            "--max-chunk-bytes",
            "1024",
            "--port",
        ])
        .arg(port.to_string())
        .arg("--data-dir")
        .arg(&dir)
        .env("DS_MAX_CHUNK_BYTES", "64")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    assert_eq!(
        first_page_end(&mut child, port, 4000),
        1024,
        "the flag must win over DS_MAX_CHUNK_BYTES"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An unusable environment value is a misconfiguration, not something to ignore
/// silently and serve unbounded responses for.
#[test]
fn invalid_env_value_refuses_to_start() {
    let dir = tmp_dir("bad-env");
    let out = server()
        .args(["--durability", "memory", "--port", "14991"])
        .arg("--data-dir")
        .arg(&dir)
        .env("DS_MAX_CHUNK_BYTES", "4MiB")
        .output()
        .expect("spawn");

    assert_eq!(out.status.code(), Some(2), "an invalid value must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("DS_MAX_CHUNK_BYTES"),
        "the refusal must name the variable that fixes it; got: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
