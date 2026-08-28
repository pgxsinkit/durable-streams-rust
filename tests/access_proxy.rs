use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType,
};

struct ChildGuard(Child);

impl ChildGuard {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

struct TestCertificate {
    cert_pem: String,
    key_pem: String,
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn wait_for_listener(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "listener {address} did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn certificate_authority() -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "durable-streams-access test CA");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = params.self_signed(&key).unwrap();
    (certificate, key)
}

fn signed_certificate(
    ca: &Certificate,
    ca_key: &KeyPair,
    dns_or_ip: Option<&str>,
    uri_san: Option<&str>,
    usage: ExtendedKeyUsagePurpose,
) -> TestCertificate {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(
        dns_or_ip
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    if let Some(uri_san) = uri_san {
        params
            .subject_alt_names
            .push(SanType::URI(Ia5String::try_from(uri_san).unwrap()));
    }
    params.extended_key_usages = vec![usage];
    let certificate = params.signed_by(&key, ca, ca_key).unwrap();
    TestCertificate {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
    }
}

fn write_certificate(path: &Path, certificate: &TestCertificate) -> io::Result<()> {
    fs::write(path.with_extension("pem"), &certificate.cert_pem)?;
    fs::write(path.with_extension("key"), &certificate.key_pem)
}

fn client(ca_pem: &str, identity: Option<&TestCertificate>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap());
    if let Some(identity) = identity {
        let combined = format!("{}{}", identity.cert_pem, identity.key_pem);
        builder = builder.identity(reqwest::Identity::from_pem(combined.as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

#[tokio::test]
async fn mtls_proxy_streams_enforces_scope_rotates_certificates_and_surfaces_upstream_loss() {
    let temporary = tempfile::tempdir().unwrap();
    let (ca, ca_key) = certificate_authority();
    let server_certificate = signed_certificate(
        &ca,
        &ca_key,
        Some("127.0.0.1"),
        None,
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client_one = signed_certificate(
        &ca,
        &ca_key,
        None,
        Some("spiffe://indexed/dev/circuits-engine"),
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let client_two = signed_certificate(
        &ca,
        &ca_key,
        None,
        Some("spiffe://indexed/dev/circuits-engine"),
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let agent_writer = signed_certificate(
        &ca,
        &ca_key,
        None,
        Some("spiffe://indexed/dev/agent-writer"),
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let storage_administrator = signed_certificate(
        &ca,
        &ca_key,
        None,
        Some("spiffe://indexed/dev/storage-administrator"),
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let ca_path = temporary.path().join("ca.pem");
    let server_path = temporary.path().join("server");
    fs::write(&ca_path, ca.pem()).unwrap();
    write_certificate(&server_path, &server_certificate).unwrap();
    let policy_path = temporary.path().join("policy.json");
    fs::write(
        &policy_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "global": {
                "data_concurrency": 8,
                "admin_concurrency": 2,
                "connect_timeout_ms": 100,
                "request_timeout_ms": 1000,
                "long_poll_timeout_ms": 5000,
                "max_request_body_bytes": 1048576
            },
            "identities": [
                {
                    "name": "circuits-engine-dev",
                    "uri_sans": ["spiffe://indexed/dev/circuits-engine"],
                    "max_concurrency": 8,
                    "rules": [{
                        "match": "prefix",
                        "path": "/circuits/v1/dev/stores/generation-a/",
                        "methods": ["GET", "HEAD", "PUT", "POST", "DELETE"]
                    }]
                },
                {
                    "name": "agent-writer-dev",
                    "uri_sans": ["spiffe://indexed/dev/agent-writer"],
                    "max_concurrency": 4,
                    "rules": [{
                        "match": "prefix",
                        "path": "/agent-runs/v1/dev/",
                        "methods": ["GET", "HEAD", "PUT", "POST", "DELETE"]
                    }]
                },
                {
                    "name": "storage-administrator-dev",
                    "uri_sans": ["spiffe://indexed/dev/storage-administrator"],
                    "max_concurrency": 2,
                    "admin_concurrency": 2,
                    "rules": [{
                        "match": "exact",
                        "path": "/_admin/ready",
                        "methods": ["GET"],
                        "admin": true
                    }]
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let storage_address = free_address();
    let proxy_address = free_address();
    let storage_data = temporary.path().join("storage");
    let store_id = "00000000-0000-0000-0000-000000000001";
    let store_generation = "00000000-0000-0000-0000-000000000002";
    let filesystem_uuid = "00000000-0000-0000-0000-000000000003";
    let bootstrap = Command::new(env!("CARGO_BIN_EXE_durable-streams-server"))
        .args([
            "bootstrap-store",
            "--data-dir",
            storage_data.to_str().unwrap(),
            "--store-id",
            store_id,
            "--store-generation",
            store_generation,
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
            filesystem_uuid,
            "--creation-time",
            "2026-08-28T00:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(
        bootstrap.status.success(),
        "store bootstrap failed: {}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let mut storage = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_durable-streams-server"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &storage_address.port().to_string(),
                "--durability",
                "wal",
                "--data-dir",
                storage_data.to_str().unwrap(),
                "--store-id",
                store_id,
                "--store-generation",
                store_generation,
                "--protocol-version",
                "1",
                "--layout-version",
                "1",
                "--wal-shards",
                "1",
                "--stream-lanes",
                "1",
                "--filesystem-uuid",
                filesystem_uuid,
                "--artifact-digest",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "--wal-segment-bytes",
                "1048576",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_listener(storage_address);
    let _proxy = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_durable-streams-access"))
            .args([
                "--listen",
                &proxy_address.to_string(),
                "--upstream",
                &format!("http://{storage_address}"),
                "--server-cert",
                server_path.with_extension("pem").to_str().unwrap(),
                "--server-key",
                server_path.with_extension("key").to_str().unwrap(),
                "--client-ca",
                ca_path.to_str().unwrap(),
                "--policy",
                policy_path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_listener(proxy_address);

    let stream = format!("https://{proxy_address}/circuits/v1/dev/stores/generation-a/catalog");
    let first = client(&ca.pem(), Some(&client_one));
    assert_eq!(
        first
            .put(&stream)
            .body(Vec::new())
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    assert_eq!(
        first
            .post(&stream)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body("hello")
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        first
            .get(&stream)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
        "hello"
    );

    let rotated = client(&ca.pem(), Some(&client_two));
    assert_eq!(rotated.head(&stream).send().await.unwrap().status(), 200);

    // Forks reference a second stream path. Authorizing only the destination lets a write-only
    // agent identity copy and pin Circuits data through an otherwise-owned agent stream.
    let agent = client(&ca.pem(), Some(&agent_writer));
    let exfil = format!("https://{proxy_address}/agent-runs/v1/dev/exfil");
    assert_eq!(
        agent
            .put(&exfil)
            .header(
                "stream-forked-from",
                "/circuits/v1/dev/stores/generation-a/catalog"
            )
            .header("stream-fork-offset", "now")
            .body(Vec::new())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        reqwest::Client::new()
            .head(format!("http://{storage_address}/agent-runs/v1/dev/exfil"))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "a denied fork must not reach storage"
    );

    let agent_stream = format!("https://{proxy_address}/agent-runs/v1/dev/connection-capacity");
    assert_eq!(
        agent
            .put(&agent_stream)
            .body(Vec::new())
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let mut agent_long_polls = Vec::new();
    for _ in 0..4 {
        let long_poll_client = client(&ca.pem(), Some(&agent_writer));
        let long_poll_url = format!("{agent_stream}?offset=now&live=long-poll");
        agent_long_polls.push(tokio::spawn(async move {
            long_poll_client.get(long_poll_url).send().await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let administrator = client(&ca.pem(), Some(&storage_administrator));
    let administrator_response = administrator
        .get(format!("https://{proxy_address}/_admin/ready"))
        .send()
        .await
        .unwrap();
    let administrator_status = administrator_response.status();
    let administrator_body = administrator_response.text().await.unwrap();
    assert!(
        administrator_status == 200 || administrator_status == 503,
        "the administrator request must reach the readiness endpoint rather than be capacity-rejected; got {administrator_status}: {administrator_body}"
    );
    if administrator_status == 503 {
        assert!(
            administrator_body.contains("\"status\":\"starting\"")
                && administrator_body.contains("\"recovery\":{\"completed\":true")
                && administrator_body.contains("\"satisfied\":false"),
            "a 503 is acceptable here only when the local test filesystem is below the production reserve: {administrator_body}"
        );
    }
    for request in agent_long_polls {
        request.abort();
    }

    let own_fork =
        format!("https://{proxy_address}/circuits/v1/dev/stores/generation-a/catalog-copy");
    assert_eq!(
        rotated
            .put(&own_fork)
            .header(
                "stream-forked-from",
                "/circuits/v1/dev/stores/generation-a/catalog"
            )
            .header("stream-fork-offset", "now")
            .body(Vec::new())
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    assert_eq!(
        rotated
            .get(&own_fork)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
        "hello"
    );

    let foreign = format!("https://{proxy_address}/agent-runs/v1/dev/run-1");
    assert_eq!(
        rotated
            .post(foreign)
            .body("x")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert!(client(&ca.pem(), None).head(&stream).send().await.is_err());

    storage.stop();
    assert_eq!(first.get(&stream).send().await.unwrap().status(), 502);
}
