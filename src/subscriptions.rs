//! Reserved Durable Streams subscription control plane (PROTOCOL.md §§6–7).
//!
//! This intentionally mirrors the protocol's reference server: subscription
//! state is process-local for now, while stream data and pull-wake events use
//! the normal durable stream path. See `docs/protocol-alignment.md` for the
//! remaining persistence/auth hardening needed before treating this as a
//! production-durable worker queue.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use reqwest::Url;
use ring::digest::{digest, SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{mpsc, Mutex};

use crate::api::{base64_encode, Body, Method, Req, Resp};
use crate::store::{format_offset, parse_offset, ParsedOffset, Store};

const SUBSCRIPTION_SUFFIX: &str = "/__ds/subscriptions/";
const JWKS_SUFFIX: &str = "/__ds/jwks.json";
const DEFAULT_LEASE_TTL_MS: u64 = 30_000;
const MIN_LEASE_TTL_MS: u64 = 1_000;
const MAX_LEASE_TTL_MS: u64 = 10 * 60_000;
const BEFORE_FIRST_OFFSET: &str = "-1";
const ZERO_OFFSET: &str = "0000000000000000_0000000000000000";
const MAX_RETRY_DELAY_MS: u64 = 60_000;
const MAX_SUBSCRIPTION_BODY_BYTES: usize = 1024 * 1024;
const MAX_SUBSCRIPTIONS_PER_ROOT: usize = 1024;
const MAX_SUBSCRIPTIONS: usize = 4096;
const MAX_STREAMS_PER_SUBSCRIPTION: usize = 10_000;
const MAX_PATTERN_BYTES: usize = 1024;
const MAX_PATTERN_SEGMENTS: usize = 64;
const MAX_SUBSCRIPTION_ID_BYTES: usize = 256;
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const DEFAULT_DELETION_DELIVERY_QUEUE_CAPACITY: usize = 256;
const DEFAULT_DELETION_DELIVERY_CONCURRENCY: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
enum SubscriptionKind {
    Webhook,
    PullWake,
}

impl SubscriptionKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::PullWake => "pull-wake",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SubscriptionConfig {
    kind: SubscriptionKind,
    pattern: Option<String>,
    streams: Vec<String>,
    webhook_url: Option<String>,
    wake_stream: Option<String>,
    lease_ttl_ms: u64,
    description: Option<String>,
}

#[derive(Clone, Debug)]
struct StreamLink {
    explicit: bool,
    glob: bool,
    acked_offset: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubscriptionStatus {
    Active,
    Failed,
}

impl SubscriptionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Failed => "failed",
        }
    }
}

struct Subscription {
    id: String,
    stream_root: String,
    config: SubscriptionConfig,
    callback_base_url: String,
    created_at: String,
    status: SubscriptionStatus,
    streams: BTreeMap<String, StreamLink>,
    generation: u64,
    wake_id: Option<String>,
    wake_snapshot: BTreeMap<String, String>,
    token: Option<String>,
    holder: Option<String>,
    lease_nonce: u64,
    retry_count: u32,
}

#[derive(Default)]
struct ManagerState {
    subscriptions: HashMap<String, Subscription>,
    /// Absolute paths used as pull-wake channels. Counts allow several
    /// subscriptions to share one pool while keeping every wake channel out of
    /// ordinary subscription membership.
    wake_streams: HashMap<String, usize>,
}

pub struct SubscriptionManager {
    state: Mutex<ManagerState>,
    subscription_count: AtomicUsize,
    rng: SystemRandom,
    signing_key: Ed25519KeyPair,
    signing_kid: String,
    signing_x: String,
    token_key: hmac::Key,
    http: reqwest::Client,
    public_base_url: Option<String>,
    deletion_delivery: DeletionDeliveryLane,
}

#[derive(Deserialize)]
struct RawCreateRequest {
    #[serde(rename = "type")]
    kind: String,
    pattern: Option<String>,
    streams: Option<Vec<String>>,
    webhook: Option<RawWebhook>,
    wake_stream: Option<String>,
    lease_ttl_ms: Option<u64>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct RawWebhook {
    url: String,
}

#[derive(Deserialize)]
struct StreamsRequest {
    streams: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct AckRequest {
    stream: Option<String>,
    path: Option<String>,
    offset: String,
}

#[derive(Clone, Deserialize)]
struct CallbackRequest {
    wake_id: Option<String>,
    generation: Option<u64>,
    acks: Option<Vec<AckRequest>>,
    done: Option<bool>,
}

struct StreamInfo {
    path: String,
    link_type: &'static str,
    acked_offset: String,
    tail_offset: String,
    has_pending: bool,
}

enum Route {
    Jwks,
    Base(String, String),
    Streams(String, String),
    Stream(String, String, String),
    Callback(String, String),
    Claim(String, String),
    Ack(String, String),
    Release(String, String),
    UnknownControl,
}

#[derive(Clone)]
enum Delivery {
    Webhook {
        key: String,
        generation: u64,
        wake_id: String,
    },
    PullWake {
        key: String,
        id: String,
        stream_root: String,
        wake_stream: String,
        stream: String,
        generation: u64,
        wake_id: String,
    },
}

/// A post-transition reconciliation request. The authoritative in-memory
/// deletion transition completes before this is admitted to the bounded lane.
struct DeletionReconcileIntent {
    key: String,
    store: Weak<Store>,
}

struct DeletionDeliveryLane {
    sender: mpsc::Sender<DeletionReconcileIntent>,
    receiver: Arc<Mutex<mpsc::Receiver<DeletionReconcileIntent>>>,
    concurrency: usize,
    started: AtomicBool,
    dropped: AtomicUsize,
    #[cfg(test)]
    test_hook: Option<Arc<DeletionDeliveryTestHook>>,
}

#[cfg(test)]
struct DeletionDeliveryTestHook {
    block_workers: AtomicBool,
    entered: tokio::sync::Notify,
    entered_workers: AtomicUsize,
    release: tokio::sync::watch::Sender<bool>,
    active_workers: AtomicUsize,
    peak_workers: AtomicUsize,
}

#[cfg(test)]
impl DeletionDeliveryTestHook {
    fn new() -> Arc<Self> {
        let (release, _) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            block_workers: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            entered_workers: AtomicUsize::new(0),
            release,
            active_workers: AtomicUsize::new(0),
            peak_workers: AtomicUsize::new(0),
        })
    }

    async fn wait_if_blocked(&self) {
        if !self.block_workers.load(Ordering::Acquire) {
            return;
        }
        let mut release = self.release.subscribe();
        let active = self.active_workers.fetch_add(1, Ordering::AcqRel) + 1;
        let mut peak = self.peak_workers.load(Ordering::Acquire);
        while active > peak {
            match self.peak_workers.compare_exchange_weak(
                peak,
                active,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
        self.entered_workers.fetch_add(1, Ordering::AcqRel);
        self.entered.notify_waiters();
        while !*release.borrow_and_update() {
            if release.changed().await.is_err() {
                self.active_workers.fetch_sub(1, Ordering::AcqRel);
                return;
            }
        }
        self.active_workers.fetch_sub(1, Ordering::AcqRel);
    }

    async fn wait_for_workers(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.entered.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.entered_workers.load(Ordering::Acquire) >= expected {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("bounded deletion delivery workers must start");
    }
}

impl SubscriptionManager {
    pub fn new() -> io::Result<Self> {
        Self::new_with_deletion_delivery_limits(
            DEFAULT_DELETION_DELIVERY_QUEUE_CAPACITY,
            DEFAULT_DELETION_DELIVERY_CONCURRENCY,
        )
    }

    fn new_with_deletion_delivery_limits(
        deletion_delivery_capacity: usize,
        deletion_delivery_concurrency: usize,
    ) -> io::Result<Self> {
        assert!(deletion_delivery_capacity > 0);
        assert!(deletion_delivery_concurrency > 0);
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| io::Error::other("failed to generate webhook signing key"))?;
        let signing_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| io::Error::other("failed to parse webhook signing key"))?;
        let signing_x = base64_encode(signing_key.public_key().as_ref(), BASE64_URL, false);
        let thumbprint = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{signing_x}\"}}");
        let signing_kid = format!(
            "ds_{}",
            base64_encode(
                digest(&SHA256, thumbprint.as_bytes()).as_ref(),
                BASE64_URL,
                false
            )
        );
        let mut token_secret = [0u8; 32];
        rng.fill(&mut token_secret)
            .map_err(|_| io::Error::other("failed to generate callback token key"))?;
        let public_base_url = match std::env::var("DS_PUBLIC_BASE_URL") {
            Ok(configured) if !configured.is_empty() => Some(
                validate_public_base_url(&configured)
                    .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
            ),
            _ => None,
        };
        let (deletion_delivery_sender, deletion_delivery_receiver) =
            mpsc::channel(deletion_delivery_capacity);
        Ok(Self {
            state: Mutex::new(ManagerState::default()),
            subscription_count: AtomicUsize::new(0),
            rng,
            signing_key,
            signing_kid,
            signing_x,
            token_key: hmac::Key::new(hmac::HMAC_SHA256, &token_secret),
            public_base_url,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                // A validated public URL must not redirect delivery into a
                // private address. DNS resolution still needs production
                // hardening; see docs/protocol-alignment.md.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(io::Error::other)?,
            deletion_delivery: DeletionDeliveryLane {
                sender: deletion_delivery_sender,
                receiver: Arc::new(Mutex::new(deletion_delivery_receiver)),
                concurrency: deletion_delivery_concurrency,
                started: AtomicBool::new(false),
                dropped: AtomicUsize::new(0),
                #[cfg(test)]
                test_hook: None,
            },
        })
    }

    pub async fn handle(self: &Arc<Self>, store: Arc<Store>, req: Req) -> Resp {
        if req.body.len() > MAX_SUBSCRIPTION_BODY_BYTES {
            return subscription_error(
                413,
                "REQUEST_TOO_LARGE",
                "Subscription request body is too large",
            );
        }
        let route = parse_route(&req.path);
        match route {
            Route::Jwks => {
                if req.method != Method::Get {
                    return method_not_allowed();
                }
                let body = json!({
                    "keys": [{
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": self.signing_x,
                        "kid": self.signing_kid,
                        "use": "sig",
                        "alg": "EdDSA"
                    }]
                });
                json_response_with_type(200, body, "application/jwk-set+json", true)
            }
            Route::Base(root, id) => match req.method {
                Method::Put if request_is_json(&req) => {
                    self.handle_create(store, req, root, id).await
                }
                Method::Put => json_content_type_required(),
                Method::Get => {
                    let state = self.state.lock().await;
                    match state.subscriptions.get(&subscription_key(&root, &id)) {
                        Some(subscription) => {
                            json_response(200, self.serialize(subscription, &store))
                        }
                        None => subscription_error(
                            404,
                            "SUBSCRIPTION_NOT_FOUND",
                            "Subscription not found",
                        ),
                    }
                }
                Method::Delete => {
                    let mut state = self.state.lock().await;
                    let removed = state.subscriptions.remove(&subscription_key(&root, &id));
                    if let Some(subscription) = &removed {
                        unregister_wake_stream(&mut state, subscription);
                    }
                    if removed.is_some() {
                        self.subscription_count.fetch_sub(1, Ordering::Release);
                    }
                    Resp::new(204)
                }
                _ => method_not_allowed(),
            },
            Route::Streams(root, id) => {
                if req.method != Method::Post {
                    return method_not_allowed();
                }
                if !request_is_json(&req) {
                    return json_content_type_required();
                }
                let parsed: StreamsRequest =
                    match serde_json::from_slice::<StreamsRequest>(&req.body) {
                        Ok(value) if !value.streams.is_empty() => value,
                        _ => {
                            return subscription_error(
                                400,
                                "INVALID_REQUEST",
                                "streams must be a non-empty string array",
                            )
                        }
                    };
                if parsed.streams.len() > MAX_STREAMS_PER_SUBSCRIPTION
                    || parsed.streams.iter().any(|stream| stream.is_empty())
                {
                    return subscription_error(
                        400,
                        "INVALID_REQUEST",
                        "streams must be a bounded non-empty string array",
                    );
                }
                let mut normalized = parsed
                    .streams
                    .iter()
                    .map(|stream| normalize_relative_path(stream))
                    .collect::<Vec<_>>();
                normalized.sort();
                normalized.dedup();
                if normalized
                    .iter()
                    .any(|stream| !valid_relative_stream_path(stream))
                {
                    return subscription_error(
                        400,
                        "INVALID_REQUEST",
                        "streams must contain valid relative paths",
                    );
                }
                let mut state = self.state.lock().await;
                if normalized.iter().any(|stream| {
                    state
                        .wake_streams
                        .contains_key(&absolute_stream_path(&root, stream))
                }) {
                    return subscription_error(
                        400,
                        "INVALID_REQUEST",
                        "streams must not include a registered wake stream",
                    );
                }
                let Some(subscription) = state.subscriptions.get_mut(&subscription_key(&root, &id))
                else {
                    return subscription_error(
                        404,
                        "SUBSCRIPTION_NOT_FOUND",
                        "Subscription not found",
                    );
                };
                let added = normalized
                    .iter()
                    .filter(|stream| !subscription.streams.contains_key(*stream))
                    .count();
                if subscription.streams.len().saturating_add(added) > MAX_STREAMS_PER_SUBSCRIPTION {
                    return subscription_error(
                        429,
                        "SUBSCRIPTION_LIMIT_EXCEEDED",
                        "Subscription stream limit exceeded",
                    );
                }
                for stream in normalized {
                    let tail = tail_offset(&store, &root, &stream);
                    let link = subscription.streams.entry(stream).or_insert(StreamLink {
                        explicit: false,
                        glob: false,
                        acked_offset: tail,
                    });
                    link.explicit = true;
                }
                Resp::new(204)
            }
            Route::Stream(root, id, stream_path) => {
                if req.method != Method::Delete {
                    return method_not_allowed();
                }
                let mut state = self.state.lock().await;
                let Some(subscription) = state.subscriptions.get_mut(&subscription_key(&root, &id))
                else {
                    return subscription_error(
                        404,
                        "SUBSCRIPTION_NOT_FOUND",
                        "Subscription not found",
                    );
                };
                let stream_path = normalize_relative_path(&stream_path);
                if let Some(link) = subscription.streams.get_mut(&stream_path) {
                    link.explicit = false;
                    if !link.glob {
                        subscription.streams.remove(&stream_path);
                    }
                }
                Resp::new(204)
            }
            Route::Callback(root, id) => {
                if req.method != Method::Post {
                    return method_not_allowed();
                }
                if !request_is_json(&req) {
                    return json_content_type_required();
                }
                self.handle_callback(store, req, root, id, false).await
            }
            Route::Claim(root, id) => {
                if req.method != Method::Post {
                    return method_not_allowed();
                }
                if !request_is_json(&req) {
                    return json_content_type_required();
                }
                self.handle_claim(store, req, root, id).await
            }
            Route::Ack(root, id) => {
                if req.method != Method::Post {
                    return method_not_allowed();
                }
                if !request_is_json(&req) {
                    return json_content_type_required();
                }
                self.handle_callback(store, req, root, id, true).await
            }
            Route::Release(root, id) => {
                if req.method != Method::Post {
                    return method_not_allowed();
                }
                if !request_is_json(&req) {
                    return json_content_type_required();
                }
                self.handle_release(store, req, root, id).await
            }
            Route::UnknownControl => subscription_error(
                404,
                "SUBSCRIPTION_NOT_FOUND",
                "Durable Streams control route not found",
            ),
        }
    }

    async fn handle_create(
        &self,
        store: Arc<Store>,
        req: Req,
        stream_root: String,
        id: String,
    ) -> Resp {
        let raw: RawCreateRequest = match serde_json::from_slice(&req.body) {
            Ok(value) => value,
            Err(_) => {
                return subscription_error(
                    400,
                    "INVALID_REQUEST",
                    "Request body must be valid JSON",
                )
            }
        };
        let config = match normalize_create_request(raw) {
            Ok(config) => config,
            Err(message) => return subscription_error(400, "INVALID_REQUEST", message),
        };
        if let Some(url) = &config.webhook_url {
            if let Err(message) = validate_webhook_url(url) {
                return subscription_error(400, "WEBHOOK_URL_REJECTED", message);
            }
        }
        if config.kind == SubscriptionKind::PullWake {
            if let Err(message) = validate_wake_stream(&store, &stream_root, &config) {
                return subscription_error(409, "WAKE_STREAM_INVALID", message);
            }
        }
        let callback_base_url = if config.kind == SubscriptionKind::Webhook {
            match &self.public_base_url {
                Some(url) => url.clone(),
                None => {
                    return subscription_error(
                        503,
                        "PUBLIC_BASE_URL_REQUIRED",
                        "DS_PUBLIC_BASE_URL is required for webhook subscriptions",
                    )
                }
            }
        } else {
            String::new()
        };
        let mut state = self.state.lock().await;
        let subscription_key = subscription_key(&stream_root, &id);
        if let Some(existing) = state.subscriptions.get(&subscription_key) {
            if existing.config != config {
                return subscription_error(
                    409,
                    "SUBSCRIPTION_ALREADY_EXISTS",
                    "Subscription already exists with different configuration",
                );
            }
            return json_response(200, self.serialize(existing, &store));
        }
        if state.subscriptions.len() >= MAX_SUBSCRIPTIONS {
            return subscription_error(
                429,
                "SUBSCRIPTION_LIMIT_EXCEEDED",
                "Global subscription count limit exceeded",
            );
        }
        if state
            .subscriptions
            .values()
            .filter(|subscription| subscription.stream_root == stream_root)
            .count()
            >= MAX_SUBSCRIPTIONS_PER_ROOT
        {
            return subscription_error(
                429,
                "SUBSCRIPTION_LIMIT_EXCEEDED",
                "Subscription count limit exceeded for this stream root",
            );
        }

        let mut subscription = Subscription {
            id: id.clone(),
            stream_root,
            config,
            callback_base_url,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
            status: SubscriptionStatus::Active,
            streams: BTreeMap::new(),
            generation: 0,
            wake_id: None,
            wake_snapshot: BTreeMap::new(),
            token: None,
            holder: None,
            lease_nonce: 0,
            retry_count: 0,
        };
        for stream in &subscription.config.streams {
            if state
                .wake_streams
                .contains_key(&absolute_stream_path(&subscription.stream_root, stream))
            {
                return subscription_error(
                    400,
                    "INVALID_REQUEST",
                    "streams must not include a registered wake stream",
                );
            }
            subscription.streams.insert(
                stream.clone(),
                StreamLink {
                    explicit: true,
                    glob: false,
                    acked_offset: tail_offset(&store, &subscription.stream_root, stream),
                },
            );
        }
        if let Some(pattern) = &subscription.config.pattern {
            for stream in list_streams(&store, &subscription.stream_root) {
                if !state
                    .wake_streams
                    .contains_key(&absolute_stream_path(&subscription.stream_root, &stream))
                    && subscription.config.wake_stream.as_deref() != Some(stream.as_str())
                    && glob_match(pattern, &stream)
                {
                    if subscription.streams.len() >= MAX_STREAMS_PER_SUBSCRIPTION
                        && !subscription.streams.contains_key(&stream)
                    {
                        return subscription_error(
                            429,
                            "SUBSCRIPTION_LIMIT_EXCEEDED",
                            "Subscription stream limit exceeded",
                        );
                    }
                    let tail = tail_offset(&store, &subscription.stream_root, &stream);
                    let link = subscription.streams.entry(stream).or_insert(StreamLink {
                        explicit: false,
                        glob: false,
                        acked_offset: tail,
                    });
                    link.glob = true;
                }
            }
        }
        let body = self.serialize(&subscription, &store);
        register_wake_stream(&mut state, &subscription, &store);
        state.subscriptions.insert(subscription_key, subscription);
        self.subscription_count.fetch_add(1, Ordering::Release);
        json_response(201, body)
    }

    async fn handle_claim(
        self: &Arc<Self>,
        store: Arc<Store>,
        req: Req,
        stream_root: String,
        id: String,
    ) -> Resp {
        #[derive(Deserialize)]
        struct ClaimRequest {
            worker: String,
        }
        let claim: ClaimRequest = match serde_json::from_slice::<ClaimRequest>(&req.body) {
            Ok(value) if !value.worker.is_empty() => value,
            _ => {
                return subscription_error(
                    400,
                    "INVALID_REQUEST",
                    "worker must be a non-empty string",
                )
            }
        };
        let (response, lease, delivery) = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state
                .subscriptions
                .get_mut(&subscription_key(&stream_root, &id))
            else {
                return subscription_error(404, "SUBSCRIPTION_NOT_FOUND", "Subscription not found");
            };
            if subscription.config.kind != SubscriptionKind::PullWake {
                return subscription_error(400, "INVALID_REQUEST", "Subscription is not pull-wake");
            }
            if let Some(holder) = &subscription.holder {
                return json_response(
                    409,
                    json!({"error": {
                        "code": "ALREADY_CLAIMED",
                        "current_holder": holder,
                        "generation": subscription.generation
                    }}),
                );
            }
            if !has_pending_work(subscription, &store) {
                return subscription_error(
                    409,
                    "NO_PENDING_WORK",
                    "Subscription has no pending work",
                );
            }
            let mut delivery = None;
            if subscription.wake_id.is_none() {
                delivery = Some(self.create_wake(
                    subscription,
                    &store,
                    first_pending(subscription, &store),
                ));
            }
            subscription.holder = Some(claim.worker);
            let token = self.generate_token(
                &subscription_key(&subscription.stream_root, &subscription.id),
                subscription.generation,
            );
            subscription.token = Some(token.clone());
            subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
            let lease = (
                subscription_key(&subscription.stream_root, &subscription.id),
                subscription.generation,
                subscription.wake_id.clone().unwrap_or_default(),
                subscription.lease_nonce,
                subscription.config.lease_ttl_ms,
            );
            let streams = stream_infos_json(subscription, &store, true);
            (
                json!({
                    "wake_id": subscription.wake_id,
                    "generation": subscription.generation,
                    "token": token,
                    "streams": streams,
                    "lease_ttl_ms": subscription.config.lease_ttl_ms
                }),
                lease,
                delivery,
            )
        };
        if let Some(delivery) = delivery {
            self.execute_delivery(store.clone(), delivery).await;
        }
        self.spawn_lease_expiry(store, lease);
        json_response(200, response)
    }

    async fn handle_callback(
        self: &Arc<Self>,
        store: Arc<Store>,
        req: Req,
        stream_root: String,
        id: String,
        require_pull: bool,
    ) -> Resp {
        let Some(token) = bearer_token(&req) else {
            return subscription_error(
                401,
                "TOKEN_INVALID",
                "Missing or malformed Authorization header",
            );
        };
        let request: CallbackRequest = match serde_json::from_slice(&req.body) {
            Ok(value) => value,
            Err(_) => return subscription_error(400, "INVALID_REQUEST", "Invalid JSON body"),
        };
        let key = subscription_key(&stream_root, &id);
        let token_generation = match self.validate_token(&key, &token) {
            Ok(generation) => generation,
            Err(code) => return subscription_error(401, code, "Token invalid"),
        };
        let (body, delivery, lease) = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state.subscriptions.get_mut(&key) else {
                return subscription_error(404, "SUBSCRIPTION_NOT_FOUND", "Subscription not found");
            };
            if (require_pull && subscription.config.kind != SubscriptionKind::PullWake)
                || (!require_pull && subscription.config.kind != SubscriptionKind::Webhook)
            {
                return subscription_error(400, "INVALID_REQUEST", "Subscription is not pull-wake");
            }
            if subscription.wake_id.is_none()
                || !self.token_matches(subscription.token.as_deref(), &token)
                || token_generation != subscription.generation
                || request.generation != Some(subscription.generation)
                || request.wake_id.as_deref() != subscription.wake_id.as_deref()
            {
                return subscription_error(409, "FENCED", "Wake generation is stale");
            }
            if let Err(message) = apply_acks(subscription, &request, &store) {
                return subscription_error(409, "INVALID_OFFSET", message);
            }

            let mut delivery = None;
            let mut lease = None;
            let mut next_wake = false;
            if request.done == Some(true) {
                clear_wake(subscription);
                if has_pending_work(subscription, &store) {
                    let triggered = first_pending(subscription, &store);
                    delivery = Some(self.create_wake(subscription, &store, triggered));
                    next_wake = true;
                }
            } else {
                subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
                lease = Some((
                    key.clone(),
                    subscription.generation,
                    subscription.wake_id.clone().unwrap_or_default(),
                    subscription.lease_nonce,
                    subscription.config.lease_ttl_ms,
                ));
            }
            (json!({"ok": true, "next_wake": next_wake}), delivery, lease)
        };
        if let Some(lease) = lease {
            self.spawn_lease_expiry(store.clone(), lease);
        }
        if let Some(delivery) = delivery {
            self.execute_delivery(store, delivery).await;
        }
        json_response(200, body)
    }

    async fn handle_release(
        self: &Arc<Self>,
        store: Arc<Store>,
        req: Req,
        stream_root: String,
        id: String,
    ) -> Resp {
        let Some(token) = bearer_token(&req) else {
            return subscription_error(
                401,
                "TOKEN_INVALID",
                "Missing or malformed Authorization header",
            );
        };
        let request: CallbackRequest = match serde_json::from_slice(&req.body) {
            Ok(value) => value,
            Err(_) => return subscription_error(400, "INVALID_REQUEST", "Invalid JSON body"),
        };
        let key = subscription_key(&stream_root, &id);
        let token_generation = match self.validate_token(&key, &token) {
            Ok(generation) => generation,
            Err(code) => return subscription_error(401, code, "Token invalid"),
        };
        let delivery = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state.subscriptions.get_mut(&key) else {
                return subscription_error(404, "SUBSCRIPTION_NOT_FOUND", "Subscription not found");
            };
            if subscription.config.kind != SubscriptionKind::PullWake {
                return subscription_error(400, "INVALID_REQUEST", "Subscription is not pull-wake");
            }
            if subscription.wake_id.is_none()
                || !self.token_matches(subscription.token.as_deref(), &token)
                || token_generation != subscription.generation
                || request.generation != Some(subscription.generation)
                || request.wake_id.as_deref() != subscription.wake_id.as_deref()
            {
                return subscription_error(409, "FENCED", "Wake generation is stale");
            }
            clear_wake(subscription);
            if has_pending_work(subscription, &store) {
                let triggered = first_pending(subscription, &store);
                Some(self.create_wake(subscription, &store, triggered))
            } else {
                None
            }
        };
        if let Some(delivery) = delivery {
            self.execute_delivery(store, delivery).await;
        }
        Resp::new(204)
    }

    pub async fn on_stream_append(self: &Arc<Self>, store: Arc<Store>, absolute_path: &str) {
        if self.subscription_count.load(Ordering::Acquire) == 0 {
            return;
        }
        let deliveries = {
            let mut state = self.state.lock().await;
            if state.wake_streams.contains_key(absolute_path) {
                return;
            }
            let mut deliveries = Vec::new();
            for subscription in state.subscriptions.values_mut() {
                let Some(relative) = relative_stream_path(&subscription.stream_root, absolute_path)
                else {
                    continue;
                };
                if subscription
                    .config
                    .pattern
                    .as_deref()
                    .is_some_and(|pattern| glob_match(pattern, &relative))
                {
                    if !subscription.streams.contains_key(&relative)
                        && subscription.streams.len() >= MAX_STREAMS_PER_SUBSCRIPTION
                    {
                        tracing::warn!(
                            subscription_id = subscription.id,
                            stream = relative,
                            "subscription stream limit reached; glob match not linked"
                        );
                        continue;
                    }
                    let link = subscription
                        .streams
                        .entry(relative.clone())
                        .or_insert(StreamLink {
                            explicit: false,
                            glob: false,
                            acked_offset: BEFORE_FIRST_OFFSET.to_string(),
                        });
                    link.glob = true;
                }
                if subscription.streams.contains_key(&relative)
                    && subscription.wake_id.is_none()
                    && subscription.holder.is_none()
                    && has_pending_work(subscription, &store)
                {
                    deliveries.push(self.create_wake(subscription, &store, relative.clone()));
                }
            }
            deliveries
        };
        for delivery in deliveries {
            self.execute_delivery(store.clone(), delivery).await;
        }
    }

    pub async fn on_stream_deleted(self: &Arc<Self>, store: Arc<Store>, absolute_path: &str) {
        if self.subscription_count.load(Ordering::Acquire) == 0 {
            return;
        }
        let intents = {
            let mut state = self.state.lock().await;
            apply_stream_deletion_transition(&mut state, absolute_path)
        };
        if intents.is_empty() {
            return;
        }
        self.ensure_deletion_delivery_workers();
        for key in intents {
            self.enqueue_deletion_reconcile(&store, key);
        }
    }

    fn ensure_deletion_delivery_workers(self: &Arc<Self>) {
        if self
            .deletion_delivery
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        for _ in 0..self.deletion_delivery.concurrency {
            let receiver = self.deletion_delivery.receiver.clone();
            let manager: Weak<Self> = Arc::downgrade(self);
            #[cfg(test)]
            let test_hook = self.deletion_delivery.test_hook.clone();
            tokio::spawn(async move {
                loop {
                    let intent = {
                        let mut receiver = receiver.lock().await;
                        receiver.recv().await
                    };
                    let Some(intent) = intent else { return };
                    #[cfg(test)]
                    if let Some(test_hook) = &test_hook {
                        test_hook.wait_if_blocked().await;
                    }
                    let Some(manager) = manager.upgrade() else {
                        return;
                    };
                    manager.process_deletion_reconcile(intent).await;
                }
            });
        }
    }

    fn enqueue_deletion_reconcile(&self, store: &Arc<Store>, key: String) {
        if self
            .deletion_delivery
            .sender
            .try_send(DeletionReconcileIntent {
                key,
                store: Arc::downgrade(store),
            })
            .is_err()
        {
            let dropped = self
                .deletion_delivery
                .dropped
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            if dropped.is_power_of_two() {
                tracing::warn!(
                    dropped,
                    "subscription deletion delivery lane saturated; dropping reconcile intent"
                );
            }
        }
    }

    async fn process_deletion_reconcile(self: &Arc<Self>, intent: DeletionReconcileIntent) {
        let Some(store) = intent.store.upgrade() else {
            return;
        };
        let delivery = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state.subscriptions.get_mut(&intent.key) else {
                return;
            };
            if subscription.wake_id.is_none()
                && subscription.holder.is_none()
                && has_pending_work(subscription, &store)
            {
                let triggered = first_pending(subscription, &store);
                Some(self.create_wake(subscription, &store, triggered))
            } else {
                None
            }
        };
        if let Some(delivery) = delivery {
            self.execute_deletion_delivery(store, delivery).await;
        }
    }

    async fn execute_deletion_delivery(self: &Arc<Self>, store: Arc<Store>, delivery: Delivery) {
        match delivery {
            Delivery::Webhook {
                key,
                generation,
                wake_id,
            } => {
                Arc::clone(self)
                    .deliver_webhook(store, key, generation, wake_id)
                    .await;
            }
            delivery @ Delivery::PullWake { .. } => self.execute_delivery(store, delivery).await,
        }
    }

    fn create_wake(
        &self,
        subscription: &mut Subscription,
        store: &Store,
        triggered_by: String,
    ) -> Delivery {
        subscription.generation = subscription.generation.wrapping_add(1);
        let wake_id = format!("w_{}", self.random_hex(12));
        subscription.wake_id = Some(wake_id.clone());
        subscription.wake_snapshot = stream_infos(subscription, store)
            .into_iter()
            .map(|info| (info.path, info.tail_offset))
            .collect();
        match subscription.config.kind {
            SubscriptionKind::Webhook => {
                let key = subscription_key(&subscription.stream_root, &subscription.id);
                subscription.token = Some(self.generate_token(&key, subscription.generation));
                subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
                Delivery::Webhook {
                    key,
                    generation: subscription.generation,
                    wake_id,
                }
            }
            SubscriptionKind::PullWake => {
                let key = subscription_key(&subscription.stream_root, &subscription.id);
                Delivery::PullWake {
                    key,
                    id: subscription.id.clone(),
                    stream_root: subscription.stream_root.clone(),
                    wake_stream: subscription.config.wake_stream.clone().unwrap_or_default(),
                    stream: triggered_by,
                    generation: subscription.generation,
                    wake_id,
                }
            }
        }
    }

    fn execute_delivery<'a>(
        self: &'a Arc<Self>,
        store: Arc<Store>,
        delivery: Delivery,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match delivery {
                Delivery::PullWake {
                    key,
                    id,
                    stream_root,
                    wake_stream,
                    stream,
                    generation,
                    wake_id,
                } => {
                    let event = json!({
                        "type": "wake",
                        "subscription_id": id,
                        "stream": stream,
                        "generation": generation,
                        "ts": unix_millis()
                    });
                    let absolute = absolute_stream_path(&stream_root, &wake_stream);
                    if crate::handlers::append_subscription_wake(store.clone(), absolute, event)
                        .await
                    {
                        let mut state = self.state.lock().await;
                        if let Some(subscription) = state.subscriptions.get_mut(&key) {
                            if subscription.generation == generation
                                && subscription.wake_id.as_deref() == Some(wake_id.as_str())
                            {
                                subscription.status = SubscriptionStatus::Active;
                                subscription.retry_count = 0;
                            }
                        }
                    } else {
                        tracing::warn!("subscription pull-wake stream append failed");
                        self.schedule_pull_wake_retry(
                            store,
                            Delivery::PullWake {
                                key,
                                id,
                                stream_root,
                                wake_stream,
                                stream,
                                generation,
                                wake_id,
                            },
                        )
                        .await;
                    }
                }
                Delivery::Webhook {
                    key,
                    generation,
                    wake_id,
                } => {
                    let manager = Arc::clone(self);
                    tokio::spawn(async move {
                        manager
                            .deliver_webhook(store, key, generation, wake_id)
                            .await;
                    });
                }
            }
        })
    }

    fn deliver_webhook(
        self: Arc<Self>,
        store: Arc<Store>,
        key: String,
        generation: u64,
        wake_id: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let (url, body) = {
                let state = self.state.lock().await;
                let Some(subscription) = state.subscriptions.get(&key) else {
                    return;
                };
                if subscription.generation != generation
                    || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                {
                    return;
                }
                let Some(url) = subscription.config.webhook_url.clone() else {
                    return;
                };
                let callback_url = format!(
                    "{}{}/__ds/subscriptions/{}/callback",
                    subscription.callback_base_url.trim_end_matches('/'),
                    subscription.stream_root,
                    subscription.id
                );
                let body = json!({
                    "subscription_id": subscription.id,
                    "wake_id": subscription.wake_id,
                    "generation": subscription.generation,
                    "streams": stream_infos_json(subscription, &store, true),
                    "callback_url": callback_url,
                    "callback_token": subscription.token
                })
                .to_string();
                (url, body)
            };
            let timestamp = unix_seconds();
            let signature = self
                .signing_key
                .sign(format!("{timestamp}.{body}").as_bytes());
            let signature = format!(
                "t={timestamp},kid={},ed25519={}",
                self.signing_kid,
                base64_encode(signature.as_ref(), BASE64_URL, false)
            );
            let response = self
                .http
                .post(url)
                .header("content-type", "application/json")
                .header("webhook-signature", signature)
                .body(body)
                .send()
                .await;

            let done = match response {
                Ok(response) if response.status().is_success() => {
                    response
                        .json::<Value>()
                        .await
                        .ok()
                        .and_then(|value| value.get("done").and_then(Value::as_bool))
                        == Some(true)
                }
                _ => {
                    self.schedule_webhook_retry(store, key, generation, wake_id)
                        .await;
                    return;
                }
            };

            let (delivery, lease) = {
                let mut state = self.state.lock().await;
                let Some(subscription) = state.subscriptions.get_mut(&key) else {
                    return;
                };
                if subscription.generation != generation
                    || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                {
                    return;
                }
                subscription.status = SubscriptionStatus::Active;
                subscription.retry_count = 0;
                if !done {
                    subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
                    (
                        None,
                        Some((
                            key,
                            generation,
                            wake_id,
                            subscription.lease_nonce,
                            subscription.config.lease_ttl_ms,
                        )),
                    )
                } else {
                    for (path, tail) in subscription.wake_snapshot.clone() {
                        if let Some(link) = subscription.streams.get_mut(&path) {
                            link.acked_offset = tail;
                        }
                    }
                    clear_wake(subscription);
                    if has_pending_work(subscription, &store) {
                        let triggered = first_pending(subscription, &store);
                        (
                            Some(self.create_wake(subscription, &store, triggered)),
                            None,
                        )
                    } else {
                        (None, None)
                    }
                }
            };
            if let Some(lease) = lease {
                self.spawn_lease_expiry(store.clone(), lease);
            }
            if let Some(delivery) = delivery {
                self.execute_delivery(store, delivery).await;
            }
        })
    }

    async fn schedule_webhook_retry(
        self: &Arc<Self>,
        store: Arc<Store>,
        key: String,
        generation: u64,
        wake_id: String,
    ) {
        let delay = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state.subscriptions.get_mut(&key) else {
                return;
            };
            if subscription.generation != generation
                || subscription.wake_id.as_deref() != Some(wake_id.as_str())
            {
                return;
            }
            subscription.status = SubscriptionStatus::Failed;
            subscription.retry_count = subscription.retry_count.saturating_add(1);
            let exponent = subscription.retry_count.saturating_sub(1).min(16);
            let base = 1_000u64
                .saturating_mul(1u64 << exponent)
                .min(MAX_RETRY_DELAY_MS);
            let jitter = 80 + (self.random_u16() as u64 % 41);
            base.saturating_mul(jitter) / 100
        };
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            manager
                .deliver_webhook(store, key, generation, wake_id)
                .await;
        });
    }

    async fn schedule_pull_wake_retry(self: &Arc<Self>, store: Arc<Store>, delivery: Delivery) {
        let Delivery::PullWake {
            key,
            generation,
            wake_id,
            ..
        } = &delivery
        else {
            return;
        };
        let key = key.clone();
        let generation = *generation;
        let wake_id = wake_id.clone();
        let delay = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state.subscriptions.get_mut(&key) else {
                return;
            };
            if subscription.generation != generation
                || subscription.wake_id.as_deref() != Some(wake_id.as_str())
            {
                return;
            }
            subscription.status = SubscriptionStatus::Failed;
            subscription.retry_count = subscription.retry_count.saturating_add(1);
            let exponent = subscription.retry_count.saturating_sub(1).min(16);
            let base = 1_000u64
                .saturating_mul(1u64 << exponent)
                .min(MAX_RETRY_DELAY_MS);
            let jitter = 80 + (self.random_u16() as u64 % 41);
            base.saturating_mul(jitter) / 100
        };
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            let current = {
                let state = manager.state.lock().await;
                state.subscriptions.get(&key).is_some_and(|subscription| {
                    subscription.generation == generation
                        && subscription.wake_id.as_deref() == Some(wake_id.as_str())
                })
            };
            if current {
                manager.execute_delivery(store, delivery).await;
            }
        });
    }

    fn spawn_lease_expiry(
        self: &Arc<Self>,
        store: Arc<Store>,
        lease: (String, u64, String, u64, u64),
    ) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let (id, generation, wake_id, nonce, ttl_ms) = lease;
            tokio::time::sleep(Duration::from_millis(ttl_ms)).await;
            let delivery = {
                let mut state = manager.state.lock().await;
                let Some(subscription) = state.subscriptions.get_mut(&id) else {
                    return;
                };
                if subscription.generation != generation
                    || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                    || subscription.lease_nonce != nonce
                {
                    return;
                }
                clear_wake(subscription);
                if has_pending_work(subscription, &store) {
                    let triggered = first_pending(subscription, &store);
                    Some(manager.create_wake(subscription, &store, triggered))
                } else {
                    None
                }
            };
            if let Some(delivery) = delivery {
                manager.execute_delivery(store, delivery).await;
            }
        });
    }

    fn serialize(&self, subscription: &Subscription, store: &Store) -> Value {
        let mut object = Map::new();
        object.insert("id".into(), json!(subscription.id));
        object.insert("subscription_id".into(), json!(subscription.id));
        object.insert("type".into(), json!(subscription.config.kind.as_str()));
        if let Some(pattern) = &subscription.config.pattern {
            object.insert("pattern".into(), json!(pattern));
        }
        object.insert(
            "streams".into(),
            Value::Array(stream_infos_json(subscription, store, false)),
        );
        if subscription.config.kind == SubscriptionKind::Webhook {
            let url = subscription
                .config
                .webhook_url
                .as_deref()
                .expect("normalized webhook subscription has a URL");
            object.insert(
                "webhook".into(),
                json!({
                    "url": url,
                    "signing": {
                        "alg": "ed25519",
                        "kid": self.signing_kid,
                        "jwks_url": format!(
                            "{}{}{}",
                            subscription.callback_base_url.trim_end_matches('/'),
                            subscription.stream_root,
                            JWKS_SUFFIX
                        )
                    }
                }),
            );
        }
        object.insert("wake_stream".into(), json!(subscription.config.wake_stream));
        object.insert(
            "lease_ttl_ms".into(),
            json!(subscription.config.lease_ttl_ms),
        );
        object.insert("created_at".into(), json!(subscription.created_at));
        object.insert("status".into(), json!(subscription.status.as_str()));
        if let Some(description) = &subscription.config.description {
            object.insert("description".into(), json!(description));
        }
        Value::Object(object)
    }

    fn generate_token(&self, id: &str, generation: u64) -> String {
        let expires = unix_seconds().saturating_add(3_600);
        let nonce = self.random_hex(12);
        let unsigned = format!("{generation}.{expires}.{nonce}");
        let signed = format!("{id}:{unsigned}");
        let signature = hmac::sign(&self.token_key, signed.as_bytes());
        format!("{unsigned}.{}", hex_encode(signature.as_ref()))
    }

    fn validate_token(&self, id: &str, token: &str) -> Result<u64, &'static str> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            return Err("TOKEN_INVALID");
        }
        let generation = parts[0].parse::<u64>().map_err(|_| "TOKEN_INVALID")?;
        let expires = parts[1].parse::<u64>().map_err(|_| "TOKEN_INVALID")?;
        let signature = hex_decode(parts[3]).ok_or("TOKEN_INVALID")?;
        let unsigned = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        let signed = format!("{id}:{unsigned}");
        hmac::verify(&self.token_key, signed.as_bytes(), &signature)
            .map_err(|_| "TOKEN_INVALID")?;
        if unix_seconds() > expires {
            return Err("TOKEN_EXPIRED");
        }
        Ok(generation)
    }

    fn token_matches(&self, expected: Option<&str>, presented: &str) -> bool {
        expected.is_some_and(|expected| {
            let expected_tag = hmac::sign(&self.token_key, expected.as_bytes());
            hmac::verify(&self.token_key, presented.as_bytes(), expected_tag.as_ref()).is_ok()
        })
    }

    fn random_hex(&self, bytes: usize) -> String {
        let mut value = vec![0u8; bytes];
        self.rng.fill(&mut value).expect("system RNG failed");
        hex_encode(&value)
    }

    fn random_u16(&self) -> u16 {
        let mut value = [0u8; 2];
        self.rng.fill(&mut value).expect("system RNG failed");
        u16::from_be_bytes(value)
    }
}

fn normalize_create_request(raw: RawCreateRequest) -> Result<SubscriptionConfig, &'static str> {
    let kind = match raw.kind.as_str() {
        "webhook" => SubscriptionKind::Webhook,
        "pull-wake" => SubscriptionKind::PullWake,
        _ => return Err("type must be \"webhook\" or \"pull-wake\""),
    };
    let pattern = raw
        .pattern
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| normalize_relative_path(&pattern));
    if pattern.as_deref().is_some_and(|pattern| {
        pattern.len() > MAX_PATTERN_BYTES
            || pattern.split('/').count() > MAX_PATTERN_SEGMENTS
            || !valid_relative_stream_path(pattern)
    }) {
        return Err("pattern is too complex or targets a reserved path");
    }
    let mut streams: Vec<String> = raw
        .streams
        .unwrap_or_default()
        .into_iter()
        .map(|stream| normalize_relative_path(&stream))
        .collect();
    if streams.len() > MAX_STREAMS_PER_SUBSCRIPTION
        || streams
            .iter()
            .any(|stream| !valid_relative_stream_path(stream))
    {
        return Err("streams must contain only bounded, valid relative paths");
    }
    streams.sort();
    streams.dedup();
    if pattern.is_none() && streams.is_empty() {
        return Err("At least one of pattern or streams is required");
    }
    let lease_ttl_ms = raw.lease_ttl_ms.unwrap_or(DEFAULT_LEASE_TTL_MS);
    if !(MIN_LEASE_TTL_MS..=MAX_LEASE_TTL_MS).contains(&lease_ttl_ms) {
        return Err("lease_ttl_ms must be an integer from 1000 to 600000");
    }
    let webhook_url = raw.webhook.map(|webhook| webhook.url);
    if kind == SubscriptionKind::Webhook && webhook_url.as_deref().map_or(true, str::is_empty) {
        return Err("webhook subscriptions require webhook.url");
    }
    if kind == SubscriptionKind::PullWake && webhook_url.is_some() {
        return Err("pull-wake subscriptions must not include webhook");
    }
    let wake_stream = raw
        .wake_stream
        .filter(|stream| !stream.is_empty())
        .map(|stream| normalize_relative_path(&stream));
    if kind == SubscriptionKind::PullWake && wake_stream.is_none() {
        return Err("pull-wake subscriptions require wake_stream");
    }
    if kind == SubscriptionKind::Webhook && wake_stream.is_some() {
        return Err("webhook subscriptions must not include wake_stream");
    }
    if wake_stream
        .as_deref()
        .is_some_and(|stream| !valid_relative_stream_path(stream))
    {
        return Err("wake_stream must be a valid non-reserved relative path");
    }
    if wake_stream
        .as_ref()
        .is_some_and(|wake_stream| streams.contains(wake_stream))
    {
        return Err("streams must not explicitly include wake_stream");
    }
    if raw
        .description
        .as_deref()
        .is_some_and(|description| description.len() > 4096)
    {
        return Err("description is too long");
    }
    Ok(SubscriptionConfig {
        kind,
        pattern,
        streams,
        webhook_url,
        wake_stream,
        lease_ttl_ms,
        description: raw.description,
    })
}

fn parse_route(path: &str) -> Route {
    let Some(control_index) = crate::reserved_paths::control_segment_index(path) else {
        return Route::UnknownControl;
    };
    let root = path[..control_index].to_string();
    let control = &path[control_index..];
    if control == JWKS_SUFFIX {
        return Route::Jwks;
    }
    let Some(rest) = control.strip_prefix(SUBSCRIPTION_SUFFIX) else {
        return Route::UnknownControl;
    };
    let mut parts = rest.split('/');
    let Some(raw_id) = parts.next().filter(|id| !id.is_empty()) else {
        return Route::UnknownControl;
    };
    let Ok(id) = percent_encoding::percent_decode_str(raw_id).decode_utf8() else {
        return Route::UnknownControl;
    };
    if !valid_subscription_id(&id) {
        return Route::UnknownControl;
    }
    let tail: Vec<&str> = parts.collect();
    if tail.is_empty() {
        return Route::Base(root, id.into_owned());
    }
    match tail.as_slice() {
        ["streams"] => Route::Streams(root, id.into_owned()),
        ["streams", stream @ ..] if !stream.is_empty() => {
            let encoded = stream.join("/");
            match percent_encoding::percent_decode_str(&encoded).decode_utf8() {
                Ok(path) => Route::Stream(root, id.into_owned(), path.into_owned()),
                Err(_) => Route::UnknownControl,
            }
        }
        ["callback"] => Route::Callback(root, id.into_owned()),
        ["claim"] => Route::Claim(root, id.into_owned()),
        ["ack"] => Route::Ack(root, id.into_owned()),
        ["release"] => Route::Release(root, id.into_owned()),
        _ => Route::UnknownControl,
    }
}

pub fn is_control_path(path: &str) -> bool {
    crate::reserved_paths::is_control_path(path)
}

fn valid_subscription_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SUBSCRIPTION_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn validate_webhook_url(raw: &str) -> Result<(), &'static str> {
    let url = Url::parse(raw).map_err(|_| "webhook.url must be a valid URL")?;
    let host = url
        .host_str()
        .ok_or("webhook.url must include a hostname")?
        .to_ascii_lowercase();
    // `Url::host_str` retains IPv6 brackets, so strip them before parsing;
    // otherwise literal loopback/ULA/link-local IPv6 addresses fall through as
    // apparently public domain names.
    let ip_host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(&host);
    let ip = ip_host.parse::<IpAddr>().ok();
    match url.scheme() {
        "http" if host == "localhost" => Ok(()),
        "http" if matches!(ip, Some(IpAddr::V4(ip)) if ip.octets()[0] == 127) => Ok(()),
        "http" => Err("http webhook URLs are only allowed for localhost or 127.0.0.x"),
        "https" if host == "localhost" => {
            Err("localhost webhook URLs must use http for development")
        }
        "https" if matches!(ip, Some(IpAddr::V6(_))) => Err("IPv6 webhook hosts are not accepted"),
        "https" if matches!(ip, Some(IpAddr::V4(ip)) if private_ipv4(ip)) => {
            Err("webhook.url must not target private or link-local hosts")
        }
        "https" => Ok(()),
        _ => Err("webhook.url must use https"),
    }
}

fn private_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0)
        || (a == 198 && matches!(b, 18 | 19))
        || a >= 240
}

fn normalize_relative_path(path: &str) -> String {
    path.trim_matches('/').to_string()
}

fn valid_relative_stream_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains('\0')
        && !path.contains('?')
        && !path.contains('#')
        && !path.contains("//")
        && !path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        && path.split('/').next() != Some("__ds")
}

fn validate_wake_stream(
    store: &Store,
    stream_root: &str,
    config: &SubscriptionConfig,
) -> Result<(), &'static str> {
    let Some(wake_stream) = config.wake_stream.as_deref() else {
        return Err("pull-wake subscriptions require wake_stream");
    };
    let Some(stream) = store.get(&absolute_stream_path(stream_root, wake_stream)) else {
        return Err("wake_stream must be created before the subscription");
    };
    if stream.shared.read().unwrap().soft_deleted {
        return Err("wake_stream is deleted");
    }
    if stream.tail().closed {
        return Err("wake_stream must be open");
    }
    if !stream.is_json {
        return Err("wake_stream must use application/json");
    }
    Ok(())
}

fn relative_stream_path(stream_root: &str, absolute: &str) -> Option<String> {
    let relative = absolute.strip_prefix(stream_root)?.strip_prefix('/')?;
    if relative.is_empty() || relative == "__ds" || relative.starts_with("__ds/") {
        return None;
    }
    Some(relative.to_string())
}

fn list_streams(store: &Store, stream_root: &str) -> Vec<String> {
    store
        .streams
        .iter()
        .filter_map(|entry| relative_stream_path(stream_root, entry.key()))
        .collect()
}

fn absolute_stream_path(stream_root: &str, relative: &str) -> String {
    format!(
        "{}/{}",
        stream_root.trim_end_matches('/'),
        normalize_relative_path(relative)
    )
}

fn tail_offset(store: &Store, stream_root: &str, relative: &str) -> String {
    live_tail_offset(store, stream_root, relative).unwrap_or_else(|| format_offset(0))
}

fn live_tail_offset(store: &Store, stream_root: &str, relative: &str) -> Option<String> {
    store
        .get(&absolute_stream_path(stream_root, relative))
        .filter(|stream| !stream.shared.read().unwrap().soft_deleted)
        .map(|stream| format_offset(stream.tail().bytes))
}

fn stream_infos(subscription: &Subscription, store: &Store) -> Vec<StreamInfo> {
    subscription
        .streams
        .iter()
        .map(|(path, link)| {
            let live_tail = live_tail_offset(store, &subscription.stream_root, path);
            let tail = live_tail.clone().unwrap_or_else(|| format_offset(0));
            StreamInfo {
                path: path.clone(),
                link_type: if link.explicit { "explicit" } else { "glob" },
                acked_offset: link.acked_offset.clone(),
                has_pending: live_tail.is_some() && tail != ZERO_OFFSET && tail > link.acked_offset,
                tail_offset: tail,
            }
        })
        .collect()
}

fn stream_infos_json(subscription: &Subscription, store: &Store, include_live: bool) -> Vec<Value> {
    stream_infos(subscription, store)
        .into_iter()
        .map(|info| {
            if include_live {
                json!({
                    "path": info.path,
                    "link_type": info.link_type,
                    "acked_offset": info.acked_offset,
                    "tail_offset": info.tail_offset,
                    "has_pending": info.has_pending
                })
            } else {
                json!({
                    "path": info.path,
                    "link_type": info.link_type,
                    "acked_offset": info.acked_offset
                })
            }
        })
        .collect()
}

fn has_pending_work(subscription: &Subscription, store: &Store) -> bool {
    subscription.streams.iter().any(|(path, link)| {
        live_tail_offset(store, &subscription.stream_root, path)
            .is_some_and(|tail| tail != ZERO_OFFSET && tail > link.acked_offset)
    })
}

fn first_pending(subscription: &Subscription, store: &Store) -> String {
    subscription
        .streams
        .iter()
        .find(|(path, link)| {
            live_tail_offset(store, &subscription.stream_root, path)
                .is_some_and(|tail| tail != ZERO_OFFSET && tail > link.acked_offset)
        })
        .map(|(path, _)| path.clone())
        .unwrap_or_default()
}

fn apply_acks(
    subscription: &mut Subscription,
    request: &CallbackRequest,
    store: &Store,
) -> Result<(), &'static str> {
    let Some(acks) = &request.acks else {
        return Ok(());
    };
    for ack in acks {
        let stream = normalize_relative_path(
            ack.stream
                .as_deref()
                .or(ack.path.as_deref())
                .unwrap_or_default(),
        );
        let Some(link) = subscription.streams.get(&stream) else {
            return Err("Ack references an unknown subscription stream");
        };
        if ack.offset == BEFORE_FIRST_OFFSET
            || !matches!(parse_offset(Some(&ack.offset)), Ok(ParsedOffset::At(_)))
            || ack.offset < link.acked_offset
            || ack.offset > tail_offset(store, &subscription.stream_root, &stream)
        {
            return Err("Ack offset is invalid for the subscription stream");
        }
    }
    for ack in acks {
        let stream = normalize_relative_path(
            ack.stream
                .as_deref()
                .or(ack.path.as_deref())
                .unwrap_or_default(),
        );
        subscription
            .streams
            .get_mut(&stream)
            .expect("ack validated")
            .acked_offset = ack.offset.clone();
    }
    Ok(())
}

fn clear_wake(subscription: &mut Subscription) {
    subscription.holder = None;
    subscription.token = None;
    subscription.wake_id = None;
    subscription.wake_snapshot.clear();
    subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
    subscription.status = SubscriptionStatus::Active;
    subscription.retry_count = 0;
}

/// Apply the authoritative, process-local deletion transition. This deliberately
/// has no Store access: once the manager lock is released, a path may be reused
/// regardless of whether asynchronous delivery reconciliation is admitted.
fn apply_stream_deletion_transition(state: &mut ManagerState, absolute_path: &str) -> Vec<String> {
    let mut intents = Vec::new();
    for (key, subscription) in &mut state.subscriptions {
        let Some(relative) = relative_stream_path(&subscription.stream_root, absolute_path) else {
            continue;
        };
        let was_linked = subscription.streams.contains_key(&relative);
        let was_wake_stream = subscription.config.wake_stream.as_deref() == Some(relative.as_str());
        let wake_mentions_deleted = subscription.wake_snapshot.contains_key(&relative);
        if !was_linked && !was_wake_stream {
            continue;
        }
        let mut remove_link = false;
        if let Some(link) = subscription.streams.get_mut(&relative) {
            if link.explicit {
                // Explicit membership survives deletion/recreation, but starts
                // at the recreated stream's fresh offset lifetime.
                link.glob = false;
                link.acked_offset = ZERO_OFFSET.to_string();
            } else {
                remove_link = true;
            }
        }
        if remove_link {
            subscription.streams.remove(&relative);
        }
        // A claimed worker may still safely finish work for other streams. Its
        // snapshot simply drops this deleted, non-pending link. Unclaimed
        // wakes that describe the deleted incarnation are stale and reset
        // before the path can be reused.
        if subscription.holder.is_none() && (was_wake_stream || wake_mentions_deleted) {
            clear_wake(subscription);
        } else if subscription.holder.is_some() {
            subscription.wake_snapshot.remove(&relative);
        }
        intents.push(key.clone());
    }
    intents
}

fn subscription_key(stream_root: &str, id: &str) -> String {
    format!("{stream_root}\0{id}")
}

fn register_wake_stream(state: &mut ManagerState, subscription: &Subscription, store: &Store) {
    if subscription.config.kind != SubscriptionKind::PullWake {
        return;
    }
    if let Some(wake_stream) = subscription.config.wake_stream.as_deref() {
        let absolute = absolute_stream_path(&subscription.stream_root, wake_stream);
        *state.wake_streams.entry(absolute.clone()).or_default() += 1;
        // A path can become a wake channel after other subscriptions have
        // already glob-linked it. Remove it retroactively from every
        // subscription that can address the same absolute path so nested-root
        // worker pools cannot wake each other indefinitely.
        for existing in state.subscriptions.values_mut() {
            let Some(relative) = relative_stream_path(&existing.stream_root, &absolute) else {
                continue;
            };
            if existing.streams.remove(&relative).is_some() {
                existing.wake_snapshot.remove(&relative);
                if existing.wake_id.is_some()
                    && existing.holder.is_none()
                    && !has_pending_work(existing, store)
                {
                    clear_wake(existing);
                }
            }
        }
    }
}

fn unregister_wake_stream(state: &mut ManagerState, subscription: &Subscription) {
    if subscription.config.kind != SubscriptionKind::PullWake {
        return;
    }
    let Some(wake_stream) = subscription.config.wake_stream.as_deref() else {
        return;
    };
    let absolute = absolute_stream_path(&subscription.stream_root, wake_stream);
    if let Some(count) = state.wake_streams.get_mut(&absolute) {
        *count -= 1;
        if *count == 0 {
            state.wake_streams.remove(&absolute);
        }
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let path: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    // Dynamic programming avoids the exponential recursion caused by several
    // `**` segments. `matched[j]` means the consumed pattern matches the first
    // `j` path segments.
    let mut matched = vec![false; path.len() + 1];
    matched[0] = true;
    for pattern_segment in pattern {
        let mut next = vec![false; path.len() + 1];
        match pattern_segment {
            "**" => {
                next[0] = matched[0];
                for index in 1..=path.len() {
                    next[index] = matched[index] || next[index - 1];
                }
            }
            "*" => {
                next[1..].copy_from_slice(&matched[..path.len()]);
            }
            literal => {
                for index in 1..=path.len() {
                    next[index] = matched[index - 1] && literal == path[index - 1];
                }
            }
        }
        matched = next;
    }
    matched[path.len()]
}

fn bearer_token(req: &Req) -> Option<String> {
    req.header("authorization")
        .and_then(|header| header.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

fn validate_public_base_url(configured: &str) -> Result<String, &'static str> {
    let url = Url::parse(configured).map_err(|_| "DS_PUBLIC_BASE_URL must be a valid URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host_str().is_none()
    {
        return Err("DS_PUBLIC_BASE_URL must be an origin URL without credentials, path, or query");
    }
    let host = url.host_str().unwrap_or_default();
    let local_http = url.scheme() == "http"
        && (host == "localhost"
            || host
                .parse::<Ipv4Addr>()
                .is_ok_and(|ip| ip.octets()[0] == 127));
    if url.scheme() != "https" && !local_http {
        return Err("DS_PUBLIC_BASE_URL must use https except for local development");
    }
    Ok(url.origin().ascii_serialization())
}

fn request_is_json(req: &Req) -> bool {
    req.header("content-type")
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn json_content_type_required() -> Resp {
    subscription_error(
        415,
        "UNSUPPORTED_MEDIA_TYPE",
        "Subscription request bodies require Content-Type: application/json",
    )
}

fn json_response(status: u16, body: Value) -> Resp {
    json_response_with_type(status, body, "application/json", false)
}

fn json_response_with_type(
    status: u16,
    body: Value,
    content_type: &'static str,
    cache_jwks: bool,
) -> Resp {
    let mut response = Resp::new(status);
    response
        .headers
        .push(("content-type", content_type.to_string()));
    if cache_jwks {
        response
            .headers
            .push(("cache-control", "public, max-age=300".to_string()));
    }
    response.body = Body::Full(Bytes::from(body.to_string()));
    response
}

fn subscription_error(status: u16, code: &'static str, message: &'static str) -> Resp {
    json_response(status, json!({"error": {"code": code, "message": message}}))
}

fn method_not_allowed() -> Resp {
    let mut response = Resp::new(405);
    response
        .headers
        .push(("content-type", "text/plain".to_string()));
    response.body = Body::Full(Bytes::from_static(b"Method not allowed"));
    response
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::{handle, test_support::DurabilityGuard};
    use crate::tier::TierConfig;
    use std::sync::atomic::AtomicU64;

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_store(name: &str) -> (Arc<Store>, std::path::PathBuf) {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ds-subscriptions-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        (
            Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap()),
            dir,
        )
    }

    fn test_subscription(
        id: &str,
        streams: BTreeMap<String, StreamLink>,
        wake_stream: Option<&str>,
    ) -> Subscription {
        Subscription {
            id: id.into(),
            stream_root: "/root".into(),
            config: SubscriptionConfig {
                kind: if wake_stream.is_some() {
                    SubscriptionKind::PullWake
                } else {
                    SubscriptionKind::Webhook
                },
                pattern: Some("events/*".into()),
                streams: Vec::new(),
                webhook_url: wake_stream
                    .is_none()
                    .then(|| "http://127.0.0.1:1/hook".into()),
                wake_stream: wake_stream.map(str::to_string),
                lease_ttl_ms: 30_000,
                description: None,
            },
            callback_base_url: "http://localhost:4562".into(),
            created_at: "2026-08-28T00:00:00Z".into(),
            status: SubscriptionStatus::Failed,
            streams,
            generation: 7,
            wake_id: Some("stale-wake".into()),
            wake_snapshot: BTreeMap::from([("events/a".into(), format_offset(9))]),
            token: Some("stale-token".into()),
            holder: Some("stale-holder".into()),
            lease_nonce: 3,
            retry_count: 2,
        }
    }

    fn test_manager(
        capacity: usize,
        concurrency: usize,
        hook: Option<Arc<DeletionDeliveryTestHook>>,
    ) -> Arc<SubscriptionManager> {
        let mut manager =
            SubscriptionManager::new_with_deletion_delivery_limits(capacity, concurrency).unwrap();
        manager.deletion_delivery.test_hook = hook;
        Arc::new(manager)
    }

    async fn insert_test_subscription(manager: &SubscriptionManager, subscription: Subscription) {
        let key = subscription_key(&subscription.stream_root, &subscription.id);
        manager
            .state
            .lock()
            .await
            .subscriptions
            .insert(key, subscription);
        manager.subscription_count.fetch_add(1, Ordering::Release);
    }

    fn json_request(method: Method, path: impl Into<String>, body: Value) -> Req {
        Req {
            method,
            path: path.into(),
            query: None,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Bytes::from(body.to_string()),
        }
    }

    fn response_json(response: Resp) -> Value {
        let Body::Full(body) = response.body else {
            panic!("expected a JSON response body")
        };
        serde_json::from_slice(&body).unwrap()
    }

    async fn create_json_stream(store: &Arc<Store>, path: &str) {
        let response = handle(store.clone(), json_request(Method::Put, path, json!([]))).await;
        assert_eq!(response.status, 201, "create {path}");
    }

    #[test]
    fn subscription_delete_transition_explicit_reset_glob_removal_and_stale_wake_clear() {
        let mut state = ManagerState::default();
        let mut explicit = test_subscription(
            "explicit",
            BTreeMap::from([(
                "events/a".into(),
                StreamLink {
                    explicit: true,
                    glob: true,
                    acked_offset: format_offset(9),
                },
            )]),
            None,
        );
        let mut glob = test_subscription(
            "glob",
            BTreeMap::from([(
                "events/a".into(),
                StreamLink {
                    explicit: false,
                    glob: true,
                    acked_offset: format_offset(9),
                },
            )]),
            None,
        );
        explicit.holder = None;
        glob.holder = None;
        state
            .subscriptions
            .insert(subscription_key("/root", "explicit"), explicit);
        state
            .subscriptions
            .insert(subscription_key("/root", "glob"), glob);

        let intents = apply_stream_deletion_transition(&mut state, "/root/events/a");
        assert_eq!(intents.len(), 2);
        let explicit = state
            .subscriptions
            .get(&subscription_key("/root", "explicit"))
            .unwrap();
        let link = explicit.streams.get("events/a").unwrap();
        assert!(link.explicit);
        assert!(!link.glob);
        assert_eq!(link.acked_offset, ZERO_OFFSET);
        assert!(explicit.wake_id.is_none());
        assert!(explicit.wake_snapshot.is_empty());
        assert!(explicit.token.is_none());
        assert!(explicit.holder.is_none());
        assert_eq!(explicit.status, SubscriptionStatus::Active);
        assert!(!state
            .subscriptions
            .get(&subscription_key("/root", "glob"))
            .unwrap()
            .streams
            .contains_key("events/a"));
    }

    #[test]
    fn subscription_delete_transition_wake_stream_clears_stale_wake_without_store_access() {
        let mut state = ManagerState::default();
        let mut subscription = test_subscription("pull", BTreeMap::new(), Some("events/a"));
        subscription.holder = None;
        state
            .subscriptions
            .insert(subscription_key("/root", "pull"), subscription);

        let intents = apply_stream_deletion_transition(&mut state, "/root/events/a");
        assert_eq!(intents, vec![subscription_key("/root", "pull")]);
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "pull"))
            .unwrap();
        assert!(subscription.wake_id.is_none());
        assert!(subscription.wake_snapshot.is_empty());
        assert!(subscription.token.is_none());
        assert!(subscription.holder.is_none());
    }

    #[test]
    fn subscription_delete_transition_claimed_wake_stream_keeps_lease_identity() {
        let mut state = ManagerState::default();
        let mut subscription = test_subscription("pull", BTreeMap::new(), Some("wake/pool"));
        subscription
            .wake_snapshot
            .insert("wake/pool".into(), format_offset(12));
        let expected_identity = (
            subscription.holder.clone(),
            subscription.wake_id.clone(),
            subscription.token.clone(),
            subscription.lease_nonce,
            subscription.generation,
        );
        state
            .subscriptions
            .insert(subscription_key("/root", "pull"), subscription);

        let intents = apply_stream_deletion_transition(&mut state, "/root/wake/pool");
        assert_eq!(intents, vec![subscription_key("/root", "pull")]);
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "pull"))
            .unwrap();
        assert_eq!(
            (
                subscription.holder.clone(),
                subscription.wake_id.clone(),
                subscription.token.clone(),
                subscription.lease_nonce,
                subscription.generation,
            ),
            expected_identity
        );
        assert_eq!(
            subscription.wake_snapshot,
            BTreeMap::from([("events/a".into(), format_offset(9))])
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscription_delete_transition_returns_before_blocked_delivery_worker() {
        let (store, directory) = test_store("blocked-delivery");
        let hook = DeletionDeliveryTestHook::new();
        hook.block_workers.store(true, Ordering::Release);
        let manager = test_manager(1, 1, Some(hook.clone()));
        insert_test_subscription(
            &manager,
            test_subscription(
                "sub-1",
                BTreeMap::from([(
                    "events/a".into(),
                    StreamLink {
                        explicit: true,
                        glob: false,
                        acked_offset: format_offset(9),
                    },
                )]),
                None,
            ),
        )
        .await;
        let entered = hook.entered.notified();
        tokio::pin!(entered);
        entered.as_mut().enable();

        tokio::time::timeout(
            Duration::from_secs(5),
            manager.on_stream_deleted(store.clone(), "/root/events/a"),
        )
        .await
        .expect("logical transition must not await delivery");
        tokio::time::timeout(Duration::from_secs(5), entered)
            .await
            .expect("bounded worker must receive the later reconcile intent");
        let state = manager.state.lock().await;
        let link = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap()
            .streams
            .get("events/a")
            .unwrap();
        assert_eq!(link.acked_offset, ZERO_OFFSET);
        drop(state);
        hook.release.send_replace(true);

        drop(manager);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscription_delete_transition_weak_intents_do_not_retain_manager_or_store() {
        let (store, directory) = test_store("weak-intents");
        let hook = DeletionDeliveryTestHook::new();
        hook.block_workers.store(true, Ordering::Release);
        let manager = test_manager(2, 1, Some(hook.clone()));
        for id in ["one", "two"] {
            insert_test_subscription(
                &manager,
                test_subscription(
                    id,
                    BTreeMap::from([(
                        "events/a".into(),
                        StreamLink {
                            explicit: true,
                            glob: false,
                            acked_offset: format_offset(5),
                        },
                    )]),
                    None,
                ),
            )
            .await;
        }
        let weak_manager = Arc::downgrade(&manager);
        let weak_store = Arc::downgrade(&store);

        manager
            .on_stream_deleted(store.clone(), "/root/events/a")
            .await;
        hook.wait_for_workers(1).await;
        drop(manager);
        drop(store);

        assert!(weak_manager.upgrade().is_none());
        assert!(weak_store.upgrade().is_none());
        hook.release.send_replace(true);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscription_delete_transition_queue_saturation_drops_without_rollback() {
        let (store, directory) = test_store("queue-saturation");
        let hook = DeletionDeliveryTestHook::new();
        hook.block_workers.store(true, Ordering::Release);
        let manager = test_manager(1, 1, Some(hook.clone()));
        for id in ["one", "two", "three"] {
            insert_test_subscription(
                &manager,
                test_subscription(
                    id,
                    BTreeMap::from([(
                        "events/a".into(),
                        StreamLink {
                            explicit: true,
                            glob: true,
                            acked_offset: format_offset(5),
                        },
                    )]),
                    None,
                ),
            )
            .await;
        }
        let entered = hook.entered.notified();
        tokio::pin!(entered);
        entered.as_mut().enable();

        manager
            .on_stream_deleted(store.clone(), "/root/events/a")
            .await;
        assert_eq!(
            manager.deletion_delivery.dropped.load(Ordering::Acquire),
            2,
            "capacity one admits one reconcile intent and drops the remainder"
        );
        tokio::time::timeout(Duration::from_secs(5), entered)
            .await
            .expect("one worker must block on the admitted intent");
        assert_eq!(hook.peak_workers.load(Ordering::Acquire), 1);
        let state = manager.state.lock().await;
        for id in ["one", "two", "three"] {
            let link = state
                .subscriptions
                .get(&subscription_key("/root", id))
                .unwrap()
                .streams
                .get("events/a")
                .unwrap();
            assert!(!link.glob);
            assert_eq!(link.acked_offset, ZERO_OFFSET);
        }
        drop(state);
        hook.release.send_replace(true);

        drop(manager);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscription_delete_transition_lane_concurrency_is_bounded() {
        let (store, directory) = test_store("bounded-concurrency");
        let hook = DeletionDeliveryTestHook::new();
        hook.block_workers.store(true, Ordering::Release);
        let manager = test_manager(3, 2, Some(hook.clone()));
        for id in ["one", "two", "three"] {
            insert_test_subscription(
                &manager,
                test_subscription(
                    id,
                    BTreeMap::from([(
                        "events/a".into(),
                        StreamLink {
                            explicit: true,
                            glob: false,
                            acked_offset: format_offset(5),
                        },
                    )]),
                    None,
                ),
            )
            .await;
        }

        manager
            .on_stream_deleted(store.clone(), "/root/events/a")
            .await;
        hook.wait_for_workers(2).await;
        assert_eq!(hook.peak_workers.load(Ordering::Acquire), 2);
        assert_eq!(
            manager.deletion_delivery.dropped.load(Ordering::Acquire),
            0,
            "capacity three admits all three intents while two workers run"
        );
        hook.release.send_replace(true);

        drop(manager);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn protocol_globs_match_segments() {
        assert_eq!(format_offset(0), ZERO_OFFSET);
        assert!(glob_match("events/*", "events/a"));
        assert!(!glob_match("events/*", "events/a/b"));
        assert!(glob_match("events/**", "events"));
        assert!(glob_match("events/**", "events/a/b"));
        assert!(glob_match("**/**/**/**/**/**/**/**/x", "a/b/c/d/e/f/g/h/x"));
        assert!(!glob_match(
            "**/**/**/**/**/**/**/**/x",
            "a/b/c/d/e/f/g/h/y"
        ));
    }

    #[test]
    fn webhook_url_policy_allows_only_explicit_local_http() {
        assert!(validate_webhook_url("http://127.0.0.1:1234/hook").is_ok());
        assert!(validate_webhook_url("http://localhost:1234/hook").is_ok());
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://100.64.0.5/hook").is_err());
        assert!(validate_webhook_url("https://192.0.0.5/hook").is_err());
        assert!(validate_webhook_url("https://198.18.0.1/hook").is_err());
        assert!(validate_webhook_url("https://224.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://240.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://[::1]/hook").is_err());
        assert!(validate_webhook_url("https://[fd00::1]/hook").is_err());
        assert!(validate_webhook_url("https://[::ffff:10.0.0.1]/hook").is_err());
        assert!(validate_webhook_url("https://worker.example/hook").is_ok());
    }

    #[test]
    fn public_callback_origin_is_operator_configured_and_canonical() {
        assert_eq!(
            validate_public_base_url("https://streams.example:8443").unwrap(),
            "https://streams.example:8443"
        );
        assert_eq!(
            validate_public_base_url("http://localhost:4562").unwrap(),
            "http://localhost:4562"
        );
        assert!(validate_public_base_url("http://evil.example").is_err());
        assert!(validate_public_base_url("https://user@streams.example").is_err());
        assert!(validate_public_base_url("https://streams.example/prefix").is_err());
    }

    #[test]
    fn pull_wake_cannot_explicitly_subscribe_to_its_own_wake_stream() {
        let raw = serde_json::from_value(json!({
            "type": "pull-wake",
            "streams": ["wake/pool"],
            "wake_stream": "wake/pool"
        }))
        .unwrap();
        assert!(normalize_create_request(raw).is_err());
        let raw = serde_json::from_value(json!({
            "type": "pull-wake",
            "pattern": "events/*",
            "wake_stream": "wake/pool",
            "webhook": {"url": "https://worker.example/hook"}
        }))
        .unwrap();
        assert!(normalize_create_request(raw).is_err());
    }

    #[test]
    fn reserved_routes_preserve_the_implementation_defined_stream_root() {
        let root = "/circuits/v1/dev/store/group-a";
        let path = format!("{root}/__ds/subscriptions/sub-1/claim");
        match parse_route(&path) {
            Route::Claim(parsed_root, id) => {
                assert_eq!(parsed_root, root);
                assert_eq!(id, "sub-1");
            }
            _ => panic!("expected a claim route"),
        }

        assert!(is_control_path(&path));
        assert!(!is_control_path(&format!("{root}/events/__ds-not-control")));
        assert!(is_control_path(&format!(
            "{root}/__ds/subscriptions/sub-1/unknown/__dsy"
        )));
        match parse_route(&format!(
            "{root}/__ds/subscriptions/sub-1/streams/__ds/subscriptions/sub-2"
        )) {
            Route::Stream(parsed_root, id, _) => {
                assert_eq!(parsed_root, root);
                assert_eq!(id, "sub-1");
            }
            _ => panic!("the first reserved segment must define the control root"),
        }
        assert!(matches!(
            parse_route(&format!("{root}/__ds/subscriptions/bad%2Fid")),
            Route::UnknownControl
        ));
        assert_eq!(
            relative_stream_path(root, &format!("{root}/events/a")),
            Some("events/a".to_string())
        );
        assert_eq!(
            absolute_stream_path(root, "wake/pool-a"),
            format!("{root}/wake/pool-a")
        );
        assert_eq!(
            relative_stream_path(root, "/circuits/v1/dev/store/group-ab/events/a"),
            None,
            "a neighboring root must not leak into this subscription"
        );
    }

    #[tokio::test]
    async fn pull_wake_requires_an_existing_open_json_wake_stream() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("missing-wake");
        let response = handle(
            store.clone(),
            json_request(
                Method::Put,
                "/root/__ds/subscriptions/sub-1",
                json!({
                    "type": "pull-wake",
                    "pattern": "events/*",
                    "wake_stream": "wake/missing"
                }),
            ),
        )
        .await;
        assert_eq!(response.status, 409);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pull_wake_stream_is_not_matched_by_its_own_glob() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("self-wake");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;

        let created = handle(
            store.clone(),
            json_request(
                Method::Put,
                "/root/__ds/subscriptions/sub-1",
                json!({
                    "type": "pull-wake",
                    "pattern": "**",
                    "wake_stream": "wake/pool",
                    "lease_ttl_ms": 600000
                }),
            ),
        )
        .await;
        assert_eq!(created.status, 201);

        let appended = handle(
            store.clone(),
            json_request(Method::Post, "/root/events/a", json!({"value": 1})),
        )
        .await;
        assert_eq!(appended.status, 204);
        let wake_tail = store.get("/root/wake/pool").unwrap().tail().bytes;
        assert!(wake_tail > 0);

        let claim = handle(
            store.clone(),
            json_request(
                Method::Post,
                "/root/__ds/subscriptions/sub-1/claim",
                json!({"worker": "worker-1"}),
            ),
        )
        .await;
        assert_eq!(claim.status, 200);
        let claim = response_json(claim);
        assert!(claim["streams"]
            .as_array()
            .unwrap()
            .iter()
            .all(|stream| stream["path"] != "wake/pool"));
        let source = claim["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stream| stream["path"] == "events/a")
            .unwrap();
        let mut ack = json_request(
            Method::Post,
            "/root/__ds/subscriptions/sub-1/ack",
            json!({
                "wake_id": claim["wake_id"],
                "generation": claim["generation"],
                "acks": [{"stream": "events/a", "offset": source["tail_offset"]}],
                "done": true
            }),
        );
        ack.headers.push((
            "authorization".into(),
            format!("Bearer {}", claim["token"].as_str().unwrap()),
        ));
        let acked = handle(store.clone(), ack).await;
        assert_eq!(acked.status, 200);
        assert_eq!(
            store.get("/root/wake/pool").unwrap().tail().bytes,
            wake_tail,
            "acking the only source event must not generate a wake about the wake stream"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn dynamically_discovered_empty_stream_is_not_pending() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("empty-dynamic-stream");
        create_json_stream(&store, "/root/wake/pool").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "pattern": "**",
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );
        create_json_stream(&store, "/root/events/new").await;
        assert_eq!(store.get("/root/wake/pool").unwrap().tail().bytes, 0);
        let state = store.subscriptions.state.lock().await;
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap();
        assert_eq!(subscription.generation, 0);
        assert!(!has_pending_work(subscription, &store));
        drop(state);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deleting_a_stream_fences_its_wake_and_allows_the_next_stream_to_wake() {
        let _fault_guard = crate::store::DELETE_FAULT_LOCK.lock().await;
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("delete-wake");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        create_json_stream(&store, "/root/events/b").await;
        let created = handle(
            store.clone(),
            json_request(
                Method::Put,
                "/root/__ds/subscriptions/sub-1",
                json!({
                    "type": "pull-wake",
                    "pattern": "events/*",
                    "wake_stream": "wake/pool"
                }),
            ),
        )
        .await;
        assert_eq!(created.status, 201);

        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let first_wake_tail = store.get("/root/wake/pool").unwrap().tail().bytes;
        let deleted = handle(
            store.clone(),
            Req {
                method: Method::Delete,
                path: "/root/events/a".into(),
                query: None,
                headers: vec![],
                body: Bytes::new(),
            },
        )
        .await;
        assert_eq!(deleted.status, 204);

        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/b", json!({"value": 2})),
            )
            .await
            .status,
            204
        );
        assert!(
            store.get("/root/wake/pool").unwrap().tail().bytes > first_wake_tail,
            "the outstanding wake for the deleted stream must not suppress later work"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deleting_an_explicit_stream_does_not_leave_phantom_pending_work() {
        let _fault_guard = crate::store::DELETE_FAULT_LOCK.lock().await;
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("delete-explicit");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/manual/a").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "streams": ["manual/a"],
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/manual/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let wake_tail = store.get("/root/wake/pool").unwrap().tail().bytes;
        assert_eq!(
            handle(
                store.clone(),
                Req {
                    method: Method::Delete,
                    path: "/root/manual/a".into(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            204
        );
        let claim = handle(
            store.clone(),
            json_request(
                Method::Post,
                "/root/__ds/subscriptions/sub-1/claim",
                json!({"worker": "worker-1"}),
            ),
        )
        .await;
        assert_eq!(
            claim.status, 409,
            "an absent explicit stream is not pending"
        );
        assert_eq!(
            store.get("/root/wake/pool").unwrap().tail().bytes,
            wake_tail
        );

        create_json_stream(&store, "/root/manual/a").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/manual/a", json!({"value": 2})),
            )
            .await
            .status,
            204
        );
        assert!(store.get("/root/wake/pool").unwrap().tail().bytes > wake_tail);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn registered_wake_streams_are_excluded_from_every_subscription() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("two-wake-pools");
        create_json_stream(&store, "/root/wake/a").await;
        create_json_stream(&store, "/root/wake/b").await;
        for (id, wake_stream) in [("sub-a", "wake/a"), ("sub-b", "wake/b")] {
            assert_eq!(
                handle(
                    store.clone(),
                    json_request(
                        Method::Put,
                        format!("/root/__ds/subscriptions/{id}"),
                        json!({
                            "type": "pull-wake",
                            "pattern": "**",
                            "wake_stream": wake_stream
                        }),
                    ),
                )
                .await
                .status,
                201
            );
        }
        {
            let state = store.subscriptions.state.lock().await;
            for subscription in state.subscriptions.values() {
                assert!(!subscription.streams.contains_key("wake/a"));
                assert!(!subscription.streams.contains_key("wake/b"));
            }
        }
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/wake/a", json!({"type": "test"})),
            )
            .await
            .status,
            204
        );
        let state = store.subscriptions.state.lock().await;
        assert!(state
            .subscriptions
            .values()
            .all(|subscription| subscription.generation == 0));
        drop(state);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn retroactive_wake_stream_exclusion_handles_nested_roots() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("nested-wake-roots");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/wake/inner-wake").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/wake/__ds/subscriptions/inner",
                    json!({
                        "type": "pull-wake",
                        "pattern": "**",
                        "wake_stream": "inner-wake"
                    }),
                ),
            )
            .await
            .status,
            201
        );
        {
            let state = store.subscriptions.state.lock().await;
            assert!(state
                .subscriptions
                .get(&subscription_key("/root/wake", "inner"))
                .unwrap()
                .streams
                .contains_key("pool"));
        }
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/outer",
                    json!({
                        "type": "pull-wake",
                        "pattern": "events/*",
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );
        let state = store.subscriptions.state.lock().await;
        assert!(!state
            .subscriptions
            .get(&subscription_key("/root/wake", "inner"))
            .unwrap()
            .streams
            .contains_key("pool"));
        drop(state);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn dynamic_glob_membership_stops_at_the_stream_limit() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("glob-limit");
        let streams = (0..MAX_STREAMS_PER_SUBSCRIPTION)
            .map(|index| {
                (
                    format!("existing/{index}"),
                    StreamLink {
                        explicit: false,
                        glob: true,
                        acked_offset: format_offset(0),
                    },
                )
            })
            .collect();
        let subscription = Subscription {
            id: "sub-1".into(),
            stream_root: "/root".into(),
            config: SubscriptionConfig {
                kind: SubscriptionKind::Webhook,
                pattern: Some("**".into()),
                streams: Vec::new(),
                webhook_url: Some("http://127.0.0.1:1/hook".into()),
                wake_stream: None,
                lease_ttl_ms: 30_000,
                description: None,
            },
            callback_base_url: "http://localhost:4562".into(),
            created_at: "2026-08-28T00:00:00Z".into(),
            status: SubscriptionStatus::Active,
            streams,
            generation: 0,
            wake_id: None,
            wake_snapshot: BTreeMap::new(),
            token: None,
            holder: None,
            lease_nonce: 0,
            retry_count: 0,
        };
        store
            .subscriptions
            .state
            .lock()
            .await
            .subscriptions
            .insert(subscription_key("/root", "sub-1"), subscription);
        store
            .subscriptions
            .subscription_count
            .fetch_add(1, Ordering::Release);
        store
            .subscriptions
            .clone()
            .on_stream_append(store.clone(), "/root/overflow")
            .await;
        let state = store.subscriptions.state.lock().await;
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap();
        assert_eq!(subscription.streams.len(), MAX_STREAMS_PER_SUBSCRIPTION);
        assert!(!subscription.streams.contains_key("overflow"));
        drop(state);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deleting_an_unrelated_link_does_not_fence_a_claimed_worker() {
        let _fault_guard = crate::store::DELETE_FAULT_LOCK.lock().await;
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("delete-while-claimed");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/b").await;
        create_json_stream(&store, "/root/events/c").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "pattern": "events/*",
                        "wake_stream": "wake/pool",
                        "lease_ttl_ms": 600000
                    }),
                ),
            )
            .await
            .status,
            201
        );
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/b", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let claim = handle(
            store.clone(),
            json_request(
                Method::Post,
                "/root/__ds/subscriptions/sub-1/claim",
                json!({"worker": "worker-1"}),
            ),
        )
        .await;
        assert_eq!(claim.status, 200);
        let claim = response_json(claim);
        let source = claim["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stream| stream["path"] == "events/b")
            .unwrap();
        assert_eq!(
            handle(
                store.clone(),
                Req {
                    method: Method::Delete,
                    path: "/root/events/c".into(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            204
        );
        let mut ack = json_request(
            Method::Post,
            "/root/__ds/subscriptions/sub-1/ack",
            json!({
                "wake_id": claim["wake_id"],
                "generation": claim["generation"],
                "acks": [{"stream": "events/b", "offset": source["tail_offset"]}],
                "done": true
            }),
        );
        ack.headers.push((
            "authorization".into(),
            format!("Bearer {}", claim["token"].as_str().unwrap()),
        ));
        assert_eq!(handle(store.clone(), ack).await.status, 200);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failed_pull_wake_delivery_retries_after_the_wake_stream_returns() {
        let _fault_guard = crate::store::DELETE_FAULT_LOCK.lock().await;
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("retry-wake");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "pattern": "events/*",
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );
        assert_eq!(
            handle(
                store.clone(),
                Req {
                    method: Method::Delete,
                    path: "/root/wake/pool".into(),
                    query: None,
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            204
        );
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        create_json_stream(&store, "/root/wake/pool").await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if store.get("/root/wake/pool").unwrap().tail().bytes > 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the scheduled delivery must recover without another source append"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        store.subscriptions.state.lock().await.subscriptions.clear();
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failed_webhook_backoff_is_not_preempted_by_the_lease_timer() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("webhook-backoff");
        create_json_stream(&store, "/root/events/a").await;
        let subscription = Subscription {
            id: "sub-1".into(),
            stream_root: "/root".into(),
            config: SubscriptionConfig {
                kind: SubscriptionKind::Webhook,
                pattern: Some("events/*".into()),
                streams: Vec::new(),
                webhook_url: Some("http://127.0.0.1:1/hook".into()),
                wake_stream: None,
                lease_ttl_ms: 1000,
                description: None,
            },
            callback_base_url: "http://localhost:4562".into(),
            created_at: "2026-08-28T00:00:00Z".into(),
            status: SubscriptionStatus::Active,
            streams: BTreeMap::from([(
                "events/a".into(),
                StreamLink {
                    explicit: false,
                    glob: true,
                    acked_offset: tail_offset(&store, "/root", "events/a"),
                },
            )]),
            generation: 0,
            wake_id: None,
            wake_snapshot: BTreeMap::new(),
            token: None,
            holder: None,
            lease_nonce: 0,
            retry_count: 0,
        };
        store
            .subscriptions
            .state
            .lock()
            .await
            .subscriptions
            .insert(subscription_key("/root", "sub-1"), subscription);
        store
            .subscriptions
            .subscription_count
            .fetch_add(1, Ordering::Release);
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let failed = store
                .subscriptions
                .state
                .lock()
                .await
                .subscriptions
                .get(&subscription_key("/root", "sub-1"))
                .is_some_and(|subscription| subscription.status == SubscriptionStatus::Failed);
            if failed {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let state = store.subscriptions.state.lock().await;
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap();
        assert_eq!(
            subscription.generation, 1,
            "delivery failure must retry the same wake instead of generating one wake per lease TTL"
        );
        assert_eq!(subscription.status, SubscriptionStatus::Failed);
        drop(state);
        store.subscriptions.state.lock().await.subscriptions.clear();
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
