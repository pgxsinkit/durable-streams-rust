use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{
    HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, LOCATION, TRANSFER_ENCODING,
};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalPolicy {
    pub data_concurrency: usize,
    pub admin_concurrency: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_long_poll_timeout_ms")]
    pub long_poll_timeout_ms: u64,
    #[serde(default = "default_sse_timeout_ms")]
    pub sse_timeout_ms: u64,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
}

const fn default_connect_timeout_ms() -> u64 {
    1_000
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

const fn default_long_poll_timeout_ms() -> u64 {
    35_000
}

const fn default_sse_timeout_ms() -> u64 {
    65_000
}

const fn default_max_request_body_bytes() -> u64 {
    1024 * 1024 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    pub name: String,
    pub uri_sans: Vec<String>,
    pub max_concurrency: usize,
    #[serde(default)]
    pub admin_concurrency: usize,
    #[serde(default)]
    pub append_requests_per_second: Option<u64>,
    #[serde(default)]
    pub append_bytes_per_second: Option<u64>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "match")]
    pub match_kind: MatchKind,
    pub path: String,
    pub methods: Vec<String>,
    #[serde(default)]
    pub admin: bool,
    /// Control rules are the only rules allowed to match a reserved `__ds`
    /// route. This keeps an existing broad data prefix from silently gaining
    /// subscription-management authority when the server is upgraded.
    #[serde(default)]
    pub control: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    Exact,
    Prefix,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    global: GlobalPolicy,
    identities: Vec<IdentityPolicy>,
}

#[derive(Debug)]
pub struct AccessPolicy {
    pub global: GlobalPolicy,
    identities: HashMap<String, IdentityPolicy>,
    identity_by_uri_san: HashMap<String, String>,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub identity: String,
    pub admin: bool,
}

impl AccessPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyError> {
        let file: PolicyFile = serde_json::from_slice(bytes)
            .map_err(|error| PolicyError(format!("invalid policy JSON: {error}")))?;
        if file.version != 1 {
            return Err(PolicyError(format!(
                "unsupported policy version {}; expected 1",
                file.version
            )));
        }
        if file.global.data_concurrency == 0 || file.global.admin_concurrency == 0 {
            return Err(PolicyError(
                "global data_concurrency and admin_concurrency must be greater than zero".into(),
            ));
        }
        if file.global.connect_timeout_ms == 0
            || file.global.request_timeout_ms == 0
            || file.global.long_poll_timeout_ms == 0
            || file.global.sse_timeout_ms == 0
            || file.global.max_request_body_bytes == 0
        {
            return Err(PolicyError(
                "timeouts and max_request_body_bytes must be greater than zero".into(),
            ));
        }
        if file.identities.is_empty() {
            return Err(PolicyError(
                "policy must define at least one identity".into(),
            ));
        }

        let mut identities = HashMap::new();
        let mut identity_by_uri_san = HashMap::new();
        for mut identity in file.identities {
            validate_identity(&mut identity)?;
            for uri_san in &identity.uri_sans {
                if let Some(existing) =
                    identity_by_uri_san.insert(uri_san.clone(), identity.name.clone())
                {
                    return Err(PolicyError(format!(
                        "URI SAN {uri_san:?} maps to both {existing:?} and {:?}",
                        identity.name
                    )));
                }
            }
            let name = identity.name.clone();
            if identities.insert(name.clone(), identity).is_some() {
                return Err(PolicyError(format!("duplicate identity name {name:?}")));
            }
        }
        let reserved_admin = identities.values().try_fold(0usize, |total, identity| {
            total.checked_add(identity.admin_concurrency)
        });
        let Some(reserved_admin) = reserved_admin else {
            return Err(PolicyError("identity admin capacity overflow".into()));
        };
        if reserved_admin > file.global.admin_concurrency {
            return Err(PolicyError(format!(
                "identity admin reservations total {reserved_admin}, above global admin_concurrency {}",
                file.global.admin_concurrency
            )));
        }

        Ok(Self {
            global: file.global,
            identities,
            identity_by_uri_san,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }

    pub fn authorize(
        &self,
        uri_sans: &[&str],
        method: &str,
        path: &str,
    ) -> Result<Authorization, PolicyError> {
        let path = normalize_path(path)?;
        let method = normalize_method(method)?;
        let identity = self.authenticate(uri_sans)?;
        self.authorize_identity(identity, method, &path)
    }

    fn authenticate(&self, uri_sans: &[&str]) -> Result<&IdentityPolicy, PolicyError> {
        let matched: HashSet<&str> = uri_sans
            .iter()
            .filter_map(|uri_san| self.identity_by_uri_san.get(*uri_san).map(String::as_str))
            .collect();
        let identity_name = match matched.len() {
            0 => {
                return Err(PolicyError(
                    "certificate has no configured URI SAN identity".into(),
                ))
            }
            1 => *matched.iter().next().expect("one matched identity"),
            _ => {
                return Err(PolicyError(
                    "certificate URI SANs map to ambiguous identities".into(),
                ))
            }
        };
        let identity = self
            .identities
            .get(identity_name)
            .expect("URI SAN index references identity");
        Ok(identity)
    }

    fn authorize_identity(
        &self,
        identity: &IdentityPolicy,
        method: &str,
        path: &str,
    ) -> Result<Authorization, PolicyError> {
        let is_control = crate::reserved_paths::is_control_path(path);
        let mut matching_rules = identity.rules.iter().filter(|rule| {
            rule.control == is_control
                && rule.methods.iter().any(|allowed| allowed == method)
                && match rule.match_kind {
                    MatchKind::Exact => rule.path == path,
                    MatchKind::Prefix => path.starts_with(&rule.path),
                }
        });
        let Some(rule) = matching_rules.next() else {
            return Err(PolicyError(format!(
                "identity {:?} is not authorized for {method} {path}",
                identity.name
            )));
        };
        if matching_rules.next().is_some() {
            return Err(PolicyError("request matched ambiguous policy rules".into()));
        }
        Ok(Authorization {
            identity: identity.name.clone(),
            admin: rule.admin,
        })
    }

    pub fn identity(&self, name: &str) -> Option<&IdentityPolicy> {
        self.identities.get(name)
    }
}

#[derive(Debug, Clone)]
pub struct AccessConfig {
    pub listen: SocketAddr,
    pub upstream: Uri,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: PathBuf,
    pub policy: PathBuf,
}

impl AccessConfig {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.upstream.scheme_str() != Some("http") {
            return Err(PolicyError(
                "upstream must use plain http over loopback".into(),
            ));
        }
        let Some(authority) = self.upstream.authority() else {
            return Err(PolicyError("upstream must include an authority".into()));
        };
        let host = authority.host();
        if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "[::1]" {
            return Err(PolicyError(format!(
                "upstream must be loopback, got {host:?}"
            )));
        }
        if self.upstream.path() != "/" || self.upstream.query().is_some() {
            return Err(PolicyError(
                "upstream must be an origin URL without a path or query".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RateWindow {
    started: Instant,
    requests: u64,
    bytes: u64,
}

#[derive(Debug)]
struct IdentityCapacity {
    connection_semaphore: Arc<Semaphore>,
    semaphore: Arc<Semaphore>,
    admin_semaphore: Arc<Semaphore>,
    request_rate: Option<u64>,
    byte_rate: Option<u64>,
    window: Mutex<RateWindow>,
}

#[derive(Debug)]
struct Capacity {
    data: Arc<Semaphore>,
    admin: Arc<Semaphore>,
    identities: HashMap<String, IdentityCapacity>,
}

#[derive(Debug)]
struct RequestPermits {
    _global: OwnedSemaphorePermit,
    _identity: OwnedSemaphorePermit,
}

impl Capacity {
    fn new(policy: &AccessPolicy) -> Self {
        let identities = policy
            .identities
            .values()
            .map(|identity| {
                (
                    identity.name.clone(),
                    IdentityCapacity {
                        connection_semaphore: Arc::new(Semaphore::new(identity.max_concurrency)),
                        semaphore: Arc::new(Semaphore::new(identity.max_concurrency)),
                        admin_semaphore: Arc::new(Semaphore::new(identity.admin_concurrency)),
                        request_rate: identity.append_requests_per_second,
                        byte_rate: identity.append_bytes_per_second,
                        window: Mutex::new(RateWindow {
                            started: Instant::now(),
                            requests: 0,
                            bytes: 0,
                        }),
                    },
                )
            })
            .collect();
        Self {
            data: Arc::new(Semaphore::new(policy.global.data_concurrency)),
            admin: Arc::new(Semaphore::new(policy.global.admin_concurrency)),
            identities,
        }
    }

    fn reserve_connection(&self, identity_name: &str) -> Result<OwnedSemaphorePermit, PolicyError> {
        self.identities
            .get(identity_name)
            .ok_or_else(|| PolicyError("authenticated identity has no capacity profile".into()))?
            .connection_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| PolicyError("identity connection capacity exhausted".into()))
    }

    fn reserve(
        &self,
        authorization: &Authorization,
        method: &str,
        content_length: Option<u64>,
    ) -> Result<RequestPermits, PolicyError> {
        let identity = self
            .identities
            .get(&authorization.identity)
            .ok_or_else(|| PolicyError("authorized identity has no capacity profile".into()))?;
        let is_write = matches!(method, "PUT" | "POST" | "DELETE");
        if is_write && content_length.is_none() {
            return Err(PolicyError(
                "writes require a canonical Content-Length".into(),
            ));
        }
        if is_write && (identity.request_rate.is_some() || identity.byte_rate.is_some()) {
            let mut window = identity.window.lock().expect("rate window lock poisoned");
            if window.started.elapsed() >= Duration::from_secs(1) {
                *window = RateWindow {
                    started: Instant::now(),
                    requests: 0,
                    bytes: 0,
                };
            }
            let next_requests = window.requests.saturating_add(1);
            let next_bytes = window
                .bytes
                .saturating_add(content_length.unwrap_or_default());
            if identity
                .request_rate
                .is_some_and(|limit| next_requests > limit)
                || identity.byte_rate.is_some_and(|limit| next_bytes > limit)
            {
                return Err(PolicyError("identity append rate exceeded".into()));
            }
            window.requests = next_requests;
            window.bytes = next_bytes;
        }
        let global = if authorization.admin {
            self.admin.clone()
        } else {
            self.data.clone()
        }
        .try_acquire_owned()
        .map_err(|_| PolicyError("global request capacity exhausted".into()))?;
        let identity = if authorization.admin {
            identity.admin_semaphore.clone()
        } else {
            identity.semaphore.clone()
        }
        .clone()
        .try_acquire_owned()
        .map_err(|_| PolicyError("identity request capacity exhausted".into()))?;
        Ok(RequestPermits {
            _global: global,
            _identity: identity,
        })
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
struct ResponseBodyTimeout;

impl fmt::Display for ResponseBodyTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("storage response body timed out")
    }
}

impl std::error::Error for ResponseBodyTimeout {}

/// A one-frame channel between the upstream response and the client connection. The producer owns
/// the request permits, so a client that stops reading cannot pin capacity forever: the total
/// response deadline wins even while the bounded channel is backpressured, drops the upstream body,
/// and releases both permits. A depth of one keeps streaming memory bounded without buffering the
/// response.
struct BoundedResponseBody {
    frames: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
}

impl Body for BoundedResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.frames.poll_recv(context)
    }
}

fn bounded_response_body<B>(
    mut inner: B,
    permits: RequestPermits,
    timeout: Duration,
) -> BoundedResponseBody
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (frames_tx, frames) = mpsc::channel::<Result<Frame<Bytes>, BoxError>>(1);
    tokio::spawn(async move {
        let _permits = permits;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            let frame = tokio::select! {
                _ = &mut deadline => {
                    let _ = frames_tx.try_send(Err(Box::new(ResponseBodyTimeout) as BoxError));
                    return;
                }
                frame = inner.frame() => frame,
            };
            let Some(frame) = frame else { return };
            let frame = frame.map_err(|error| -> BoxError { Box::new(error) });
            let sent = tokio::select! {
                _ = &mut deadline => false,
                sent = frames_tx.send(frame) => sent.is_ok(),
            };
            if !sent {
                return;
            }
        }
    });
    BoundedResponseBody { frames }
}

type ProxyBody = BoxBody<Bytes, BoxError>;
type ProxyClient = Client<HttpConnector, Incoming>;

fn boxed_full(body: impl Into<Bytes>) -> ProxyBody {
    Full::new(body.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(boxed_full(body))
        .expect("static proxy response")
}

pub async fn run(config: AccessConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    config.validate()?;
    let policy_bytes = std::fs::read(&config.policy)?;
    let policy = Arc::new(AccessPolicy::from_json(&policy_bytes)?);
    let capacity = Arc::new(Capacity::new(&policy));
    let tls = Arc::new(load_tls_config(
        &config.server_cert,
        &config.server_key,
        &config.client_ca,
    )?);
    let listener = TcpListener::bind(config.listen).await?;
    let mut connector = HttpConnector::new();
    connector.enforce_http(true);
    connector.set_connect_timeout(Some(Duration::from_millis(
        policy.global.connect_timeout_ms,
    )));
    let client: ProxyClient = Client::builder(TokioExecutor::new()).build(connector);
    let upstream = config
        .upstream
        .to_string()
        .trim_end_matches('/')
        .to_string();
    let handshake_capacity = policy
        .identities
        .values()
        .try_fold(0usize, |total, identity| {
            total.checked_add(identity.max_concurrency)
        })
        .ok_or_else(|| PolicyError("identity connection capacity overflow".into()))?;
    let handshakes = Arc::new(Semaphore::new(handshake_capacity));
    tracing::info!(
        listen = %config.listen,
        upstream = %upstream,
        policy_sha256 = %policy.sha256,
        "durable-streams-access ready"
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(error = %error, "storage access listener accept failed; retrying");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let handshake = match handshakes.clone().try_acquire_owned() {
            Ok(handshake) => handshake,
            Err(_) => {
                tracing::warn!(%peer, "storage access handshake capacity exhausted");
                continue;
            }
        };
        let acceptor = TlsAcceptor::from(tls.clone());
        let policy = policy.clone();
        let capacity = capacity.clone();
        let client = client.clone();
        let upstream = upstream.clone();
        let handshake_timeout = Duration::from_millis(policy.global.connect_timeout_ms);
        let header_timeout = Duration::from_millis(policy.global.request_timeout_ms);
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(error)) => {
                    tracing::warn!(%peer, error = %error, "mTLS handshake rejected");
                    return;
                }
                Err(_) => {
                    tracing::warn!(%peer, timeout_ms = handshake_timeout.as_millis() as u64, "mTLS handshake timed out");
                    return;
                }
            };
            let uri_sans = match peer_uri_sans(&tls) {
                Ok(uri_sans) if !uri_sans.is_empty() => Arc::new(uri_sans),
                Ok(_) => {
                    tracing::warn!(%peer, "mTLS certificate has no URI SAN");
                    return;
                }
                Err(error) => {
                    tracing::warn!(%peer, error = %error, "mTLS certificate identity rejected");
                    return;
                }
            };
            let uri_refs: Vec<&str> = uri_sans.iter().map(String::as_str).collect();
            let identity = match policy.authenticate(&uri_refs) {
                Ok(identity) => identity.name.clone(),
                Err(error) => {
                    tracing::warn!(%peer, error = %error, "mTLS certificate identity rejected");
                    return;
                }
            };
            let connection = match capacity.reserve_connection(&identity) {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%peer, identity, error = %error, "storage access identity connection capacity exhausted");
                    return;
                }
            };
            drop(handshake);
            let service = service_fn(move |request| {
                proxy_request(
                    request,
                    uri_sans.clone(),
                    policy.clone(),
                    capacity.clone(),
                    client.clone(),
                    upstream.clone(),
                )
            });
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(TokioTimer::new())
                .header_read_timeout(header_timeout);
            let _connection = connection;
            if let Err(error) = http.serve_connection(TokioIo::new(tls), service).await {
                tracing::debug!(%peer, error = %error, "proxy connection ended");
            }
        });
    }
}

async fn proxy_request(
    mut request: Request<Incoming>,
    uri_sans: Arc<Vec<String>>,
    policy: Arc<AccessPolicy>,
    capacity: Arc<Capacity>,
    client: ProxyClient,
    upstream: String,
) -> Result<Response<ProxyBody>, Infallible> {
    let started = Instant::now();
    let method = request.method().as_str().to_string();
    let raw_path = request.uri().path().to_string();
    let uri_refs: Vec<&str> = uri_sans.iter().map(String::as_str).collect();
    let authorization = match policy.authorize(&uri_refs, &method, &raw_path) {
        Ok(authorization) => authorization,
        Err(error) => {
            tracing::warn!(method, error = %error, "storage request denied");
            return Ok(response(StatusCode::FORBIDDEN, "forbidden\n"));
        }
    };
    let mut fork_sources = request.headers().get_all("stream-forked-from").iter();
    if let Some(source) = fork_sources.next() {
        if fork_sources.next().is_some() {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "Stream-Forked-From must appear at most once\n",
            ));
        }
        let source = match source.to_str() {
            Ok(source) => source,
            Err(_) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    "invalid Stream-Forked-From\n",
                ))
            }
        };
        match policy.authorize(&uri_refs, "GET", source) {
            Ok(source_authorization) if source_authorization.identity == authorization.identity => {
            }
            _ => {
                tracing::warn!(
                    identity = %authorization.identity,
                    method,
                    fork_source = source,
                    "storage fork source denied"
                );
                return Ok(response(StatusCode::FORBIDDEN, "fork source forbidden\n"));
            }
        }
    }
    if request.headers().contains_key(TRANSFER_ENCODING) {
        return Ok(response(
            StatusCode::LENGTH_REQUIRED,
            "chunked request bodies are not accepted\n",
        ));
    }
    let content_length = match request.headers().get(CONTENT_LENGTH) {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(length) => Some(length),
            None => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    "invalid Content-Length\n",
                ))
            }
        },
        // With no Transfer-Encoding and no Content-Length, HTTP/1 framing defines an empty body.
        None => Some(0),
    };
    if content_length.is_some_and(|length| length > policy.global.max_request_body_bytes) {
        return Ok(response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large\n",
        ));
    }
    let permits = match capacity.reserve(&authorization, &method, content_length) {
        Ok(permits) => permits,
        Err(error) => {
            let status = if error.0.contains("Content-Length") {
                StatusCode::LENGTH_REQUIRED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            };
            tracing::warn!(identity = %authorization.identity, method, error = %error, "storage request capacity denied");
            return Ok(response(status, format!("{error}\n")));
        }
    };
    let traceparent = ensure_traceparent(request.headers_mut());
    strip_hop_by_hop(request.headers_mut());
    request.headers_mut().remove(HOST);
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let target: Uri = match format!("{upstream}{path_and_query}").parse() {
        Ok(target) => target,
        Err(_) => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "invalid request target\n",
            ))
        }
    };
    *request.uri_mut() = target;

    let response_timeout = match live_mode(request.uri().query()) {
        Some(LiveMode::LongPoll) => policy.global.long_poll_timeout_ms,
        Some(LiveMode::Sse) => policy.global.sse_timeout_ms,
        None => policy.global.request_timeout_ms,
    };
    let upstream_response = match tokio::time::timeout(
        Duration::from_millis(response_timeout),
        client.request(request),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::warn!(identity = %authorization.identity, method, traceparent, error = %error, "storage upstream failed");
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "storage upstream failed\n",
            ));
        }
        Err(_) => {
            tracing::warn!(identity = %authorization.identity, method, traceparent, "storage upstream response timed out");
            return Ok(response(
                StatusCode::GATEWAY_TIMEOUT,
                "storage upstream timed out\n",
            ));
        }
    };
    let (mut parts, body) = upstream_response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    rewrite_location(&mut parts.headers);
    let status = parts.status;
    let identity = authorization.identity.clone();
    let body_budget = Duration::from_millis(response_timeout).saturating_sub(started.elapsed());
    let guarded = bounded_response_body(body, permits, body_budget).boxed();
    tracing::info!(
        identity,
        method,
        status = status.as_u16(),
        admin = authorization.admin,
        traceparent,
        duration_ms = started.elapsed().as_millis() as u64,
        "storage request admitted"
    );
    Ok(Response::from_parts(parts, guarded))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveMode {
    LongPoll,
    Sse,
}

fn live_mode(query: Option<&str>) -> Option<LiveMode> {
    query.and_then(|query| {
        query
            .split('&')
            .find_map(|part| match part.split_once('=') {
                Some(("live", "long-poll")) => Some(LiveMode::LongPoll),
                Some(("live", "sse")) => Some(LiveMode::Sse),
                _ => None,
            })
    })
}

fn rewrite_location(headers: &mut hyper::HeaderMap) {
    let Some(location) = headers.get(LOCATION) else {
        return;
    };
    let Ok(location) = location.to_str() else {
        headers.remove(LOCATION);
        return;
    };
    let Ok(uri) = location.parse::<Uri>() else {
        headers.remove(LOCATION);
        return;
    };
    if uri.scheme().is_none() && uri.authority().is_none() {
        return;
    }
    let Some(path_and_query) = uri.path_and_query() else {
        headers.remove(LOCATION);
        return;
    };
    match HeaderValue::from_str(path_and_query.as_str()) {
        Ok(location) => {
            headers.insert(LOCATION, location);
        }
        Err(_) => {
            headers.remove(LOCATION);
        }
    }
}

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let connection_tokens: Vec<HeaderName> = headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .into_iter()
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in connection_tokens {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        HeaderName::from_static("proxy-connection"),
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("transfer-encoding"),
        HeaderName::from_static("upgrade"),
    ] {
        headers.remove(name);
    }
}

fn ensure_traceparent(headers: &mut hyper::HeaderMap) -> String {
    static NEXT_TRACE: AtomicU64 = AtomicU64::new(1);
    if let Some(existing) = headers
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_traceparent(value))
    {
        return existing.to_string();
    }
    let counter = NEXT_TRACE.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(now.to_be_bytes());
    hasher.update(counter.to_be_bytes());
    let digest = hasher.finalize();
    let value = format!("00-{}-{}-01", hex(&digest[..16]), hex(&digest[16..24]));
    headers.insert(
        HeaderName::from_static("traceparent"),
        HeaderValue::from_str(&value).expect("generated traceparent is valid"),
    );
    value
}

fn valid_traceparent(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 55
        && bytes[2] == b'-'
        && bytes[35] == b'-'
        && bytes[52] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 2 | 35 | 52) || byte.is_ascii_hexdigit())
        && &value[3..35] != "00000000000000000000000000000000"
        && &value[36..52] != "0000000000000000"
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

fn load_tls_config(
    server_cert: &Path,
    server_key: &Path,
    client_ca: &Path,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let certs = read_certs(server_cert)?;
    let key = read_private_key(server_key)?;
    let mut roots = RootCertStore::empty();
    for certificate in read_certs(client_ca)? {
        roots.add(certificate)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut config =
        ServerConfig::builder_with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn read_certs(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(format!("{} contains no certificates", path.display()).into());
    }
    Ok(certs)
}

fn read_private_key(
    path: &Path,
) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| format!("{} contains no private key", path.display()).into())
}

fn peer_uri_sans<S>(
    tls: &tokio_rustls::server::TlsStream<S>,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let certificates = tls
        .get_ref()
        .1
        .peer_certificates()
        .ok_or("mTLS peer certificate missing")?;
    let leaf = certificates
        .first()
        .ok_or("mTLS peer certificate chain is empty")?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())?;
    let mut uri_sans = Vec::new();
    if let Some(subject_alt_name) = certificate.subject_alternative_name()? {
        for name in &subject_alt_name.value.general_names {
            if let GeneralName::URI(uri) = name {
                uri_sans.push((*uri).to_string());
            }
        }
    }
    Ok(uri_sans)
}

fn normalize_method(method: &str) -> Result<&str, PolicyError> {
    if method.is_empty()
        || method
            .bytes()
            .any(|byte| !matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'-'))
    {
        return Err(PolicyError(
            "HTTP method is not canonical uppercase ASCII".into(),
        ));
    }
    Ok(method)
}

pub fn normalize_path(path: &str) -> Result<String, PolicyError> {
    if !path.starts_with('/') || path.len() > 4096 {
        return Err(PolicyError(
            "path must be an absolute URI path no longer than 4096 bytes".into(),
        ));
    }
    if path.contains('%')
        || path.contains('\\')
        || path.contains("//")
        || path.contains('?')
        || path.contains('#')
    {
        return Err(PolicyError(
            "path contains an encoded or non-canonical alias".into(),
        ));
    }
    if path.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(PolicyError("path must contain visible ASCII only".into()));
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(PolicyError("path contains a dot segment".into()));
    }
    Ok(path.to_string())
}

fn validate_identity(identity: &mut IdentityPolicy) -> Result<(), PolicyError> {
    if identity.name.is_empty()
        || identity.max_concurrency == 0
        || identity.uri_sans.is_empty()
        || identity.rules.is_empty()
    {
        return Err(PolicyError(format!(
            "identity {:?} requires a name, URI SAN, positive max_concurrency, and rules",
            identity.name
        )));
    }
    if identity.append_requests_per_second == Some(0) || identity.append_bytes_per_second == Some(0)
    {
        return Err(PolicyError(format!(
            "identity {:?} rate limits must be positive",
            identity.name
        )));
    }
    let mut sans = HashSet::new();
    for uri_san in &identity.uri_sans {
        if !uri_san.starts_with("spiffe://") || !sans.insert(uri_san) {
            return Err(PolicyError(format!(
                "identity {:?} has invalid or duplicate URI SAN {uri_san:?}",
                identity.name
            )));
        }
    }
    for rule in &mut identity.rules {
        rule.path = normalize_path(&rule.path)?;
        if rule.match_kind == MatchKind::Prefix && !rule.path.ends_with('/') {
            return Err(PolicyError(format!(
                "prefix rule {:?} must end with '/'",
                rule.path
            )));
        }
        if rule.methods.is_empty() {
            return Err(PolicyError(format!("rule {:?} has no methods", rule.path)));
        }
        let mut methods = HashSet::new();
        for method in &rule.methods {
            normalize_method(method)?;
            if !methods.insert(method) {
                return Err(PolicyError(format!(
                    "rule {:?} repeats method {method}",
                    rule.path
                )));
            }
        }
        if rule.admin != rule.path.starts_with("/_admin/") {
            return Err(PolicyError(format!(
                "admin rules must be marked admin and data rules must not target /_admin/: {:?}",
                rule.path
            )));
        }
        if rule.control && rule.admin {
            return Err(PolicyError(format!(
                "control rules are data-capacity rules and must not be admin: {:?}",
                rule.path
            )));
        }
        if !rule.admin && rule.match_kind == MatchKind::Prefix && "/_admin/".starts_with(&rule.path)
        {
            return Err(PolicyError(format!(
                "data prefix rules must not cover the admin namespace: {:?}",
                rule.path
            )));
        }
        if rule.admin && rule.match_kind != MatchKind::Exact {
            return Err(PolicyError(
                "admin authorization must use exact rules".into(),
            ));
        }
    }
    let has_admin_rules = identity.rules.iter().any(|rule| rule.admin);
    if has_admin_rules && identity.admin_concurrency == 0 {
        return Err(PolicyError(format!(
            "identity {:?} has admin rules but no admin_concurrency reservation",
            identity.name
        )));
    }
    if !has_admin_rules && identity.admin_concurrency != 0 {
        return Err(PolicyError(format!(
            "identity {:?} reserves admin_concurrency without any admin rules",
            identity.name
        )));
    }
    if identity.admin_concurrency > identity.max_concurrency {
        return Err(PolicyError(format!(
            "identity {:?} admin_concurrency exceeds max_concurrency",
            identity.name
        )));
    }
    for (index, left) in identity.rules.iter().enumerate() {
        for right in identity.rules.iter().skip(index + 1) {
            // Control and ordinary data rules occupy disjoint route spaces, so
            // they may deliberately use the same root prefix.
            if left.control != right.control {
                continue;
            }
            let methods_overlap = left
                .methods
                .iter()
                .any(|method| right.methods.contains(method));
            let paths_overlap = match (left.match_kind, right.match_kind) {
                (MatchKind::Exact, MatchKind::Exact) => left.path == right.path,
                (MatchKind::Exact, MatchKind::Prefix) => left.path.starts_with(&right.path),
                (MatchKind::Prefix, MatchKind::Exact) => right.path.starts_with(&left.path),
                (MatchKind::Prefix, MatchKind::Prefix) => {
                    left.path.starts_with(&right.path) || right.path.starts_with(&left.path)
                }
            };
            if methods_overlap && paths_overlap {
                return Err(PolicyError(format!(
                    "identity {:?} has ambiguous rules {:?} and {:?}",
                    identity.name, left.path, right.path
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    fn policy() -> AccessPolicy {
        AccessPolicy::from_json(
            br#"{
              "version": 1,
              "global": {"data_concurrency": 232, "admin_concurrency": 8},
              "identities": [
                {
                  "name": "circuits-dev",
                  "uri_sans": ["spiffe://indexed/dev/circuits"],
                  "max_concurrency": 64,
                  "admin_concurrency": 1,
                  "rules": [
                    {"match": "prefix", "path": "/circuits/v1/dev/stores/generation-a/", "methods": ["GET", "HEAD", "PUT", "POST", "DELETE"]},
                    {"match": "exact", "path": "/_admin/ready", "methods": ["GET"], "admin": true}
                  ]
                },
                {
                  "name": "agent-writer-dev",
                  "uri_sans": ["spiffe://indexed/dev/agent-writer"],
                  "max_concurrency": 32,
                  "append_requests_per_second": 100,
                  "append_bytes_per_second": 8388608,
                  "rules": [
                    {"match": "prefix", "path": "/agent-runs/v1/dev/", "methods": ["PUT", "POST", "DELETE"]}
                  ]
                },
                {
                  "name": "gateway-dev",
                  "uri_sans": ["spiffe://indexed/dev/gateway"],
                  "max_concurrency": 128,
                  "rules": [
                    {"match": "prefix", "path": "/circuits/v1/dev/stores/generation-a/", "methods": ["GET", "HEAD"]},
                    {"match": "prefix", "path": "/agent-runs/v1/dev/", "methods": ["GET", "HEAD"]}
                  ]
                }
              ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn authorizes_method_and_owned_prefix_only() {
        let policy = policy();
        let allowed = policy
            .authorize(
                &["spiffe://indexed/dev/agent-writer"],
                "POST",
                "/agent-runs/v1/dev/run-1",
            )
            .unwrap();
        assert_eq!(allowed.identity, "agent-writer-dev");
        assert!(!allowed.admin);

        assert!(policy
            .authorize(
                &["spiffe://indexed/dev/agent-writer"],
                "GET",
                "/agent-runs/v1/dev/run-1",
            )
            .is_err());
        assert!(policy
            .authorize(
                &["spiffe://indexed/dev/agent-writer"],
                "POST",
                "/circuits/v1/dev/stores/generation-a/catalog",
            )
            .is_err());
        assert!(policy
            .authorize(
                &["spiffe://indexed/dev/agent-writer"],
                "POST",
                "/agent-runs/v1/dev/__ds/subscriptions/sub-1/claim",
            )
            .is_err());
    }

    #[test]
    fn control_routes_require_an_explicit_control_rule() {
        let policy = AccessPolicy::from_json(
            br#"{
              "version": 1,
              "global": {"data_concurrency": 2, "admin_concurrency": 1},
              "identities": [{
                "name":"worker",
                "uri_sans":["spiffe://worker"],
                "max_concurrency":2,
                "rules":[
                  {"match":"prefix","path":"/root/","methods":["GET","POST"]},
                  {"match":"prefix","path":"/root/","methods":["GET","POST"],"control":true}
                ]
              }]
            }"#,
        )
        .unwrap();

        assert!(policy
            .authorize(&["spiffe://worker"], "GET", "/root/events/a")
            .is_ok());
        assert!(policy
            .authorize(
                &["spiffe://worker"],
                "POST",
                "/root/__ds/subscriptions/sub-1/claim",
            )
            .is_ok());
    }

    #[test]
    fn isolates_admin_from_data_rules() {
        let policy = policy();
        assert!(policy
            .authorize(&["spiffe://indexed/dev/gateway"], "GET", "/_admin/ready",)
            .is_err());
        assert!(
            policy
                .authorize(&["spiffe://indexed/dev/circuits"], "GET", "/_admin/ready",)
                .unwrap()
                .admin
        );
    }

    #[test]
    fn rejects_ambiguous_certificate_identity() {
        let policy = policy();
        let error = policy
            .authorize(
                &[
                    "spiffe://indexed/dev/circuits",
                    "spiffe://indexed/dev/gateway",
                ],
                "GET",
                "/circuits/v1/dev/stores/generation-a/catalog",
            )
            .unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
    }

    #[test]
    fn rejects_aliasing_and_unnormalized_paths() {
        for path in [
            "/agent-runs/v1/dev/../circuits/catalog",
            "/agent-runs//v1/dev/run-1",
            "/agent-runs%2fv1/dev/run-1",
            "/agent-runs\\v1/dev/run-1",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path}");
        }
        assert_eq!(
            normalize_path("/agent-runs/v1/dev/run-1").unwrap(),
            "/agent-runs/v1/dev/run-1"
        );
    }

    #[test]
    fn rejects_duplicate_uri_san_mappings_at_startup() {
        let error = AccessPolicy::from_json(
            br#"{
              "version": 1,
              "global": {"data_concurrency": 1, "admin_concurrency": 1},
              "identities": [
                {"name":"one","uri_sans":["spiffe://same"],"max_concurrency":1,"rules":[{"match":"prefix","path":"/one/","methods":["GET"]}]},
                {"name":"two","uri_sans":["spiffe://same"],"max_concurrency":1,"rules":[{"match":"prefix","path":"/two/","methods":["GET"]}]}
              ]
            }"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("spiffe://same"));
    }

    #[test]
    fn rejects_data_prefix_that_covers_the_admin_namespace() {
        let error = AccessPolicy::from_json(
            br#"{
              "version": 1,
              "global": {"data_concurrency": 1, "admin_concurrency": 1},
              "identities": [{
                "name":"overbroad",
                "uri_sans":["spiffe://overbroad"],
                "max_concurrency":1,
                "rules":[{"match":"prefix","path":"/","methods":["GET"]}]
              }]
            }"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("admin namespace"));
    }

    #[test]
    fn rejects_admin_identity_reservations_above_the_global_pool() {
        let error = AccessPolicy::from_json(
            br#"{
              "version": 1,
              "global": {"data_concurrency": 1, "admin_concurrency": 1},
              "identities": [
                {
                  "name":"one",
                  "uri_sans":["spiffe://one"],
                  "max_concurrency":1,
                  "admin_concurrency":1,
                  "rules":[{"match":"exact","path":"/_admin/ready","methods":["GET"],"admin":true}]
                },
                {
                  "name":"two",
                  "uri_sans":["spiffe://two"],
                  "max_concurrency":1,
                  "admin_concurrency":1,
                  "rules":[{"match":"exact","path":"/_admin/inventory","methods":["GET"],"admin":true}]
                }
              ]
            }"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("above global admin_concurrency"));
    }

    #[test]
    fn identity_overload_is_rejected_without_queueing() {
        let policy = policy();
        let capacity = Capacity::new(&policy);
        let authorization = Authorization {
            identity: "gateway-dev".into(),
            admin: false,
        };
        let held: Vec<_> = (0..128)
            .map(|_| capacity.reserve(&authorization, "GET", None).unwrap())
            .collect();
        assert!(capacity
            .reserve(&authorization, "GET", None)
            .unwrap_err()
            .0
            .contains("identity"));
        drop(held);
        assert!(capacity.reserve(&authorization, "GET", None).is_ok());
    }

    #[test]
    fn admin_capacity_is_reserved_outside_data_capacity() {
        let policy = policy();
        let capacity = Capacity::new(&policy);
        let data = Authorization {
            identity: "circuits-dev".into(),
            admin: false,
        };
        let admin = Authorization {
            identity: "circuits-dev".into(),
            admin: true,
        };
        let _held: Vec<_> = (0..64)
            .map(|_| capacity.reserve(&data, "GET", None).unwrap())
            .collect();
        assert!(capacity.reserve(&admin, "GET", None).is_ok());
    }

    #[test]
    fn each_admin_identity_keeps_its_declared_share_of_global_capacity() {
        let policy =
            AccessPolicy::from_json(include_bytes!("../deploy/access-policy.example.json"))
                .unwrap();
        let capacity = Capacity::new(&policy);
        let circuits = policy
            .authorize(
                &["spiffe://indexed/dev/circuits-engine"],
                "GET",
                "/_admin/ready",
            )
            .unwrap();
        let administrator = policy
            .authorize(
                &["spiffe://indexed/dev/storage-administrator"],
                "GET",
                "/_admin/ready",
            )
            .unwrap();
        let _circuits_admin = capacity.reserve(&circuits, "GET", None).unwrap();
        assert!(capacity.reserve(&circuits, "GET", None).is_err());
        assert!(capacity.reserve(&administrator, "GET", None).is_ok());
    }

    #[test]
    fn established_connection_capacity_is_isolated_by_identity() {
        let policy = policy();
        let capacity = Capacity::new(&policy);
        let _agent_connections: Vec<_> = (0..32)
            .map(|_| capacity.reserve_connection("agent-writer-dev").unwrap())
            .collect();
        assert!(capacity.reserve_connection("agent-writer-dev").is_err());
        assert!(capacity.reserve_connection("circuits-dev").is_ok());
    }

    #[tokio::test]
    async fn stalled_response_body_releases_capacity_at_its_deadline() {
        let policy = policy();
        let capacity = Capacity::new(&policy);
        let authorization = Authorization {
            identity: "gateway-dev".into(),
            admin: false,
        };
        let permits = capacity.reserve(&authorization, "GET", None).unwrap();
        let body = bounded_response_body(PendingBody, permits, Duration::from_millis(20));
        let _held: Vec<_> = (1..128)
            .map(|_| capacity.reserve(&authorization, "GET", None).unwrap())
            .collect();
        assert!(capacity.reserve(&authorization, "GET", None).is_err());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(capacity.reserve(&authorization, "GET", None).is_ok());
        drop(body);
    }

    #[test]
    fn agent_append_budget_is_isolated_from_gateway_reads() {
        let policy = policy();
        let capacity = Capacity::new(&policy);
        let writer = Authorization {
            identity: "agent-writer-dev".into(),
            admin: false,
        };
        for _ in 0..100 {
            drop(capacity.reserve(&writer, "POST", Some(1)).unwrap());
        }
        assert!(capacity
            .reserve(&writer, "POST", Some(1))
            .unwrap_err()
            .0
            .contains("rate"));

        let gateway = Authorization {
            identity: "gateway-dev".into(),
            admin: false,
        };
        assert!(capacity.reserve(&gateway, "GET", None).is_ok());
    }

    #[test]
    fn every_write_requires_a_canonical_content_length() {
        let policy = policy();
        let capacity = Capacity::new(&policy);
        let circuits = Authorization {
            identity: "circuits-dev".into(),
            admin: false,
        };

        assert!(
            capacity
                .reserve(&circuits, "POST", None)
                .unwrap_err()
                .0
                .contains("Content-Length"),
            "chunked writes must not bypass the global body limit"
        );
        assert!(capacity.reserve(&circuits, "POST", Some(0)).is_ok());
    }

    #[test]
    fn live_timeout_selection_requires_an_exact_query_parameter() {
        assert_eq!(live_mode(Some("offset=0&live=sse")), Some(LiveMode::Sse));
        assert_eq!(
            live_mode(Some("live=long-poll&offset=0")),
            Some(LiveMode::LongPoll)
        );
        assert_eq!(live_mode(Some("x=live=sse")), None);
        assert_eq!(live_mode(Some("live=something-else")), None);
        assert_eq!(live_mode(None), None);
    }

    #[test]
    fn upstream_absolute_locations_are_rewritten_to_proxy_relative_paths() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("http://127.0.0.1:4437/streams/example?offset=42"),
        );
        rewrite_location(&mut headers);
        assert_eq!(headers.get(LOCATION).unwrap(), "/streams/example?offset=42");

        headers.insert(LOCATION, HeaderValue::from_static("/already-relative"));
        rewrite_location(&mut headers);
        assert_eq!(headers.get(LOCATION).unwrap(), "/already-relative");
    }

    #[test]
    fn example_policy_contains_the_required_admin_identities() {
        let policy =
            AccessPolicy::from_json(include_bytes!("../deploy/access-policy.example.json"))
                .expect("example policy must stay loadable");
        let ready = "/_admin/ready";
        let inventory = "/_admin/inventory";

        assert!(
            policy
                .authorize(
                    &["spiffe://indexed/dev/storage-administrator"],
                    "GET",
                    ready,
                )
                .unwrap()
                .admin
        );
        assert!(
            policy
                .authorize(
                    &["spiffe://indexed/dev/storage-administrator"],
                    "GET",
                    inventory,
                )
                .unwrap()
                .admin
        );
        assert!(
            policy
                .authorize(&["spiffe://indexed/dev/retention"], "GET", inventory)
                .unwrap()
                .admin
        );
        assert!(policy
            .authorize(&["spiffe://indexed/dev/retention"], "GET", ready)
            .is_err());
    }

    #[test]
    fn every_pilot_identity_is_checked_against_every_stream_verb_and_prefix() {
        let policy = policy();
        let methods = ["GET", "HEAD", "PUT", "POST", "DELETE"];
        let cases = [
            (
                "spiffe://indexed/dev/circuits",
                "/circuits/v1/dev/stores/generation-a/catalog",
                [true, true, true, true, true],
            ),
            (
                "spiffe://indexed/dev/circuits",
                "/agent-runs/v1/dev/run-1",
                [false, false, false, false, false],
            ),
            (
                "spiffe://indexed/dev/agent-writer",
                "/agent-runs/v1/dev/run-1",
                [false, false, true, true, true],
            ),
            (
                "spiffe://indexed/dev/agent-writer",
                "/circuits/v1/dev/stores/generation-a/catalog",
                [false, false, false, false, false],
            ),
            (
                "spiffe://indexed/dev/gateway",
                "/agent-runs/v1/dev/run-1",
                [true, true, false, false, false],
            ),
            (
                "spiffe://indexed/dev/gateway",
                "/circuits/v1/dev/stores/generation-a/catalog",
                [true, true, false, false, false],
            ),
        ];
        for (uri_san, path, expected) in cases {
            for (index, method) in methods.iter().enumerate() {
                assert_eq!(
                    policy.authorize(&[uri_san], method, path).is_ok(),
                    expected[index],
                    "unexpected decision for {uri_san} {method} {path}"
                );
            }
        }
    }
}
