//! Reserved Durable Streams subscription control plane (PROTOCOL.md §§6–7).
//!
//! Subscription definitions, cursors, wakes, leases, retries, callback-token
//! secrets, and webhook signing keys are persisted below the store data
//! directory. Delivery is therefore resumed (and fenced) across restarts.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use reqwest::Url;
use ring::digest::{digest, SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify};

use crate::api::{base64_encode, Body, Method, Req, Resp};
use crate::store::{format_offset, parse_offset, ParsedOffset, Store};
use crate::subscription_auth::{ServiceJwtError, ServiceJwtVerifier};

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
const STATE_VERSION: u32 = 1;
const SECRETS_VERSION: u32 = 1;
const DEFAULT_SIGNING_KEY_ROTATION_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_SIGNATURE_REPLAY_WINDOW_SECS: u64 = 5 * 60;
const JWKS_CACHE_MAX_AGE_SECS: u64 = 5 * 60;
const MAX_WEBHOOK_RESPONSE_BYTES: usize = 64 * 1024;
const WEBHOOK_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const ALLOW_LOCAL_WEBHOOKS_ENV: &str = "DS_WEBHOOK_ALLOW_LOCALHOST";
const MAX_PINNED_WEBHOOK_CLIENTS: usize = 256;
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SubscriptionConfig {
    kind: SubscriptionKind,
    pattern: Option<String>,
    streams: Vec<String>,
    webhook_url: Option<String>,
    wake_stream: Option<String>,
    lease_ttl_ms: u64,
    description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StreamLink {
    explicit: bool,
    glob: bool,
    acked_offset: String,
    #[serde(default)]
    stream_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    next_attempt_at_ms: Option<u64>,
    #[serde(default)]
    lease_expires_at_ms: Option<u64>,
    #[serde(default)]
    wake_trigger: Option<String>,
    #[serde(default)]
    wake_delivery_pending: bool,
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    subscriptions: Vec<Subscription>,
}

#[derive(Serialize, Deserialize)]
struct PersistedSecrets {
    version: u32,
    token_secret: String,
    active_kid: String,
    signing_keys: Vec<PersistedSigningKey>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedSigningKey {
    pkcs8: String,
    kid: String,
    x: String,
    created_at_ms: u64,
    retire_after_ms: Option<u64>,
    #[serde(default)]
    activate_after_ms: Option<u64>,
}

#[derive(Clone)]
struct SigningKeyEntry {
    pair: Arc<Ed25519KeyPair>,
    persisted: PersistedSigningKey,
    /// A monotonic lower bound paired with the persisted wall-clock deadline.
    /// Both deadlines must pass before a pre-published key becomes active.
    activate_not_before: Option<Instant>,
}

#[derive(Clone)]
struct SigningKeyRing {
    active_kid: String,
    keys: Vec<SigningKeyEntry>,
}

#[derive(Clone, Default)]
struct ManagerState {
    subscriptions: HashMap<String, Subscription>,
    /// Absolute paths used as pull-wake channels. Counts allow several
    /// subscriptions to share one pool while keeping every wake channel out of
    /// ordinary subscription membership.
    wake_streams: HashMap<String, usize>,
}

pub struct SubscriptionManager {
    state: Mutex<ManagerState>,
    /// Committed subscriptions plus creates that may have sampled stream tails.
    /// Keeping both phases in one atomic makes the append fast-path decision a
    /// coherent single read.
    subscription_count: AtomicUsize,
    rng: SystemRandom,
    state_path: PathBuf,
    dirty_revision: AtomicU64,
    persistence_scheduled: AtomicBool,
    /// Number of detached coalescing writers that have been admitted but have
    /// not fully exited yet. This is separate from `persistence_scheduled`,
    /// which intentionally has a brief handoff window while a dirty successor
    /// races the current writer.
    persistence_active: AtomicUsize,
    persistence_idle: Notify,
    persistence_sequence: AtomicU64,
    persisted_sequence: Arc<AtomicU64>,
    persistence_file_lock: Arc<StdMutex<()>>,
    secrets_path: PathBuf,
    signing_keys: StdMutex<SigningKeyRing>,
    signing_rotation_ms: u64,
    signing_replay_window_ms: u64,
    token_secret: [u8; 32],
    token_key: hmac::Key,
    service_jwt: ServiceJwtVerifier,
    public_base_url: Option<String>,
}

struct PersistenceActivity {
    manager: Arc<SubscriptionManager>,
}

impl Drop for PersistenceActivity {
    fn drop(&mut self) {
        if self
            .manager
            .persistence_active
            .fetch_sub(1, Ordering::AcqRel)
            == 1
        {
            self.manager.persistence_idle.notify_waiters();
        }
    }
}

struct SubscriptionCreateGuard<'a> {
    counter: &'a AtomicUsize,
    committed: bool,
}

impl<'a> SubscriptionCreateGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::Release);
        Self {
            counter,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for SubscriptionCreateGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.counter.fetch_sub(1, Ordering::Release);
        }
    }
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
        nonce: u64,
    },
    PullWake {
        key: String,
        id: String,
        stream_root: String,
        wake_stream: String,
        stream: String,
        generation: u64,
        wake_id: String,
        nonce: u64,
    },
}

impl SubscriptionManager {
    pub fn new(data_dir: &Path) -> io::Result<Self> {
        let rng = SystemRandom::new();
        let subscription_dir = data_dir.join("subscriptions");
        create_secure_dir(&subscription_dir)?;
        let state_path = subscription_dir.join("state.json");
        let secrets_path = subscription_dir.join("secrets.json");
        let mut state = load_persisted_state(&state_path)?;
        if !state.subscriptions.is_empty() && !secrets_path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "persisted subscriptions exist but {} is missing; refusing to replace the store's token and webhook identity",
                    secrets_path.display()
                ),
            ));
        }
        let (mut signing_keys, token_secret) = load_or_create_secrets(&secrets_path, &rng)?;
        let signing_rotation_ms = env_seconds(
            "DS_WEBHOOK_SIGNING_KEY_ROTATION_SECS",
            DEFAULT_SIGNING_KEY_ROTATION_SECS,
        )?
        .saturating_mul(1_000);
        let signing_replay_window_ms = env_seconds(
            "DS_WEBHOOK_SIGNATURE_REPLAY_WINDOW_SECS",
            DEFAULT_SIGNATURE_REPLAY_WINDOW_SECS,
        )?
        .saturating_mul(1_000);
        if signing_replay_window_ms < JWKS_CACHE_MAX_AGE_SECS.saturating_mul(1_000) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "DS_WEBHOOK_SIGNATURE_REPLAY_WINDOW_SECS must be at least {JWKS_CACHE_MAX_AGE_SECS}"
                ),
            ));
        }
        if rotate_signing_keys_if_due(
            &mut signing_keys,
            &rng,
            signing_rotation_ms,
            signing_replay_window_ms,
        )? {
            persist_secrets(&secrets_path, &signing_keys, &token_secret)?;
        }
        let public_base_url = match std::env::var("DS_PUBLIC_BASE_URL") {
            Ok(configured) if !configured.is_empty() => Some(
                validate_public_base_url(&configured)
                    .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?,
            ),
            _ => None,
        };
        if state
            .subscriptions
            .values()
            .any(|subscription| subscription.config.kind == SubscriptionKind::Webhook)
            && public_base_url.is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DS_PUBLIC_BASE_URL is required to resume persisted webhook subscriptions",
            ));
        }
        let mut wake_streams = HashMap::new();
        for subscription in state.subscriptions.values_mut() {
            if subscription.config.kind == SubscriptionKind::Webhook {
                subscription.callback_base_url = public_base_url.clone().unwrap_or_default();
            }
            if let Some(wake_stream) = subscription.config.wake_stream.as_deref() {
                *wake_streams
                    .entry(absolute_stream_path(&subscription.stream_root, wake_stream))
                    .or_default() += 1;
            }
        }
        state.wake_streams = wake_streams;
        let subscription_count = state.subscriptions.len();
        let token_key = hmac::Key::new(hmac::HMAC_SHA256, &token_secret);
        #[cfg(not(test))]
        let service_jwt = ServiceJwtVerifier::from_env()?;
        #[cfg(test)]
        let service_jwt = ServiceJwtVerifier::insecure_for_tests();
        Ok(Self {
            state: Mutex::new(state),
            subscription_count: AtomicUsize::new(subscription_count),
            rng,
            state_path,
            dirty_revision: AtomicU64::new(0),
            persistence_scheduled: AtomicBool::new(false),
            persistence_active: AtomicUsize::new(0),
            persistence_idle: Notify::new(),
            persistence_sequence: AtomicU64::new(0),
            persisted_sequence: Arc::new(AtomicU64::new(0)),
            persistence_file_lock: Arc::new(StdMutex::new(())),
            secrets_path,
            signing_keys: StdMutex::new(signing_keys),
            signing_rotation_ms,
            signing_replay_window_ms,
            token_secret,
            token_key,
            service_jwt,
            public_base_url,
        })
    }

    fn persist_state(&self, state: &ManagerState) -> io::Result<()> {
        let persisted = PersistedState {
            version: STATE_VERSION,
            subscriptions: state.subscriptions.values().cloned().collect(),
        };
        let sequence = self
            .persistence_sequence
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        persist_ordered_snapshot(
            &self.state_path,
            &self.persistence_file_lock,
            &self.persisted_sequence,
            sequence,
            &persisted,
        )
    }

    fn persist_state_for_request(&self, state: &ManagerState) -> bool {
        match self.persist_state(state) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(%error, "failed to persist subscription control state");
                false
            }
        }
    }

    fn persist_background_or_abort(&self, state: &ManagerState, transition: &str) {
        if let Err(error) = self.persist_state(state) {
            // There is no HTTP request to fail and rolling back may duplicate
            // an already-issued webhook or durable wake append. Fail-stop so
            // restart recovery replays the last durable fenced generation.
            eprintln!(
                "fatal: failed to persist subscription {transition}; refusing to continue with split durable and in-memory state: {error}"
            );
            std::process::abort();
        }
    }

    fn schedule_state_persistence(self: &Arc<Self>) {
        self.dirty_revision.fetch_add(1, Ordering::AcqRel);
        if self.persistence_scheduled.swap(true, Ordering::AcqRel) {
            return;
        }
        // Account before spawning so a drain started immediately after this
        // function returns cannot miss a task that Tokio has not polled yet.
        self.persistence_active.fetch_add(1, Ordering::AcqRel);
        let manager = Arc::clone(self);
        let activity = PersistenceActivity {
            manager: Arc::clone(&manager),
        };
        tokio::spawn(async move {
            // Move an already-created guard into the future so cancellation
            // before its first poll still releases the active slot.
            let _activity = activity;
            let mut delay_ms = 0u64;
            loop {
                if delay_ms != 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                let target_revision = manager.dirty_revision.load(Ordering::Acquire);
                // Clone the latest state under the manager lock, then release
                // it before serialization/fsync. Ordered sequence fencing in
                // persist_ordered_snapshot prevents this snapshot from
                // overwriting a newer request-committed state if writes race.
                let state = manager.state.lock().await;
                let persisted = PersistedState {
                    version: STATE_VERSION,
                    subscriptions: state.subscriptions.values().cloned().collect(),
                };
                let sequence = manager
                    .persistence_sequence
                    .fetch_add(1, Ordering::AcqRel)
                    .wrapping_add(1);
                drop(state);
                let path = manager.state_path.clone();
                let file_lock = Arc::clone(&manager.persistence_file_lock);
                let persisted_sequence = Arc::clone(&manager.persisted_sequence);
                let result = tokio::task::spawn_blocking(move || {
                    persist_ordered_snapshot(
                        &path,
                        &file_lock,
                        &persisted_sequence,
                        sequence,
                        &persisted,
                    )
                })
                .await;
                match result {
                    Ok(Ok(())) => {
                        delay_ms = 0;
                        manager
                            .persistence_scheduled
                            .store(false, Ordering::Release);
                        if manager.dirty_revision.load(Ordering::Acquire) == target_revision {
                            break;
                        }
                        // A mutation raced the write. Either its caller has
                        // already installed a successor writer, or this task
                        // reacquires responsibility and persists the latest
                        // coalesced snapshot.
                        if manager.persistence_scheduled.swap(true, Ordering::AcqRel) {
                            break;
                        }
                    }
                    Ok(Err(error)) => {
                        tracing::error!(%error, "retrying subscription state persistence");
                        delay_ms = if delay_ms == 0 {
                            100
                        } else {
                            delay_ms.saturating_mul(2).min(10_000)
                        };
                    }
                    Err(error) => {
                        tracing::error!(%error, "subscription state writer task failed");
                        delay_ms = 100;
                    }
                }
            }
        });
    }

    /// Wait until every coalescing snapshot writer admitted before or during
    /// this wait has exited. Registering the notification before observing the
    /// count prevents a final writer transition from being missed.
    #[cfg(test)]
    async fn drain_state_persistence(&self) {
        loop {
            let idle = self.persistence_idle.notified();
            tokio::pin!(idle);
            // `notify_waiters` does not store a permit. Enroll this waiter
            // before observing the active count so the final writer cannot
            // transition to zero in the gap before the first `.await` poll.
            idle.as_mut().enable();
            if self.persistence_active.load(Ordering::Acquire) == 0 {
                return;
            }
            idle.await;
        }
    }

    fn refresh_signing_keys(&self) -> io::Result<()> {
        let mut keys = self.signing_keys.lock().unwrap();
        let mut candidate = clone_signing_key_ring(&keys);
        if rotate_signing_keys_if_due(
            &mut candidate,
            &self.rng,
            self.signing_rotation_ms,
            self.signing_replay_window_ms,
        )? {
            // Publish or activate a key only after the complete candidate
            // keyring is durable. A failed write leaves the live ring exactly
            // as it was, so JWKS and signatures cannot expose an ephemeral key.
            persist_secrets(&self.secrets_path, &candidate, &self.token_secret)?;
            *keys = candidate;
        }
        Ok(())
    }

    fn active_signing_metadata(&self) -> (String, String) {
        let keys = self.signing_keys.lock().unwrap();
        let active = keys
            .keys
            .iter()
            .find(|key| key.persisted.kid == keys.active_kid)
            .expect("validated keyring always has its active key");
        (active.persisted.kid.clone(), active.persisted.x.clone())
    }

    fn jwks(&self) -> io::Result<Value> {
        self.refresh_signing_keys()?;
        let keys = self.signing_keys.lock().unwrap();
        Ok(json!({
            "keys": keys.keys.iter().map(|key| json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": key.persisted.x,
                "kid": key.persisted.kid,
                "use": "sig",
                "alg": "EdDSA"
            })).collect::<Vec<_>>()
        }))
    }

    fn sign_webhook(&self, message: &[u8]) -> io::Result<(String, String)> {
        self.refresh_signing_keys()?;
        let keys = self.signing_keys.lock().unwrap();
        let active = keys
            .keys
            .iter()
            .find(|key| key.persisted.kid == keys.active_kid)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "active signing key missing")
            })?;
        Ok((
            active.persisted.kid.clone(),
            base64_encode(active.pair.sign(message).as_ref(), BASE64_URL, false),
        ))
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
                let body = match self.jwks() {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::error!(%error, "failed to rotate webhook signing keys");
                        return internal_subscription_error();
                    }
                };
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
                    let key = subscription_key(&root, &id);
                    let removed = state.subscriptions.remove(&key);
                    if let Some(subscription) = removed {
                        unregister_wake_stream(&mut state, &subscription);
                        if !self.persist_state_for_request(&state) {
                            register_wake_stream(&mut state, &subscription, &store);
                            state.subscriptions.insert(key, subscription);
                            return internal_subscription_error();
                        }
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
                let before = subscription.clone();
                for stream in normalized {
                    let metadata = live_stream_metadata(&store, &root, &stream);
                    let tail = metadata
                        .as_ref()
                        .map(|(_, tail)| tail.clone())
                        .unwrap_or_else(|| format_offset(0));
                    let link = subscription.streams.entry(stream).or_insert(StreamLink {
                        explicit: false,
                        glob: false,
                        acked_offset: tail,
                        stream_id: metadata.map(|(id, _)| id),
                    });
                    link.explicit = true;
                }
                if !self.persist_state_for_request(&state) {
                    state
                        .subscriptions
                        .insert(subscription_key(&root, &id), before);
                    return internal_subscription_error();
                }
                Resp::new(204)
            }
            Route::Stream(root, id, stream_path) => {
                if req.method != Method::Delete {
                    return method_not_allowed();
                }
                let mut state = self.state.lock().await;
                let key = subscription_key(&root, &id);
                let Some(subscription) = state.subscriptions.get_mut(&key) else {
                    return subscription_error(
                        404,
                        "SUBSCRIPTION_NOT_FOUND",
                        "Subscription not found",
                    );
                };
                let before = subscription.clone();
                let stream_path = normalize_relative_path(&stream_path);
                if let Some(link) = subscription.streams.get_mut(&stream_path) {
                    link.explicit = false;
                    if !link.glob {
                        subscription.streams.remove(&stream_path);
                    }
                }
                if !self.persist_state_for_request(&state) {
                    state.subscriptions.insert(key, before);
                    return internal_subscription_error();
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

    /// Resume persisted retries and leases after stream/WAL recovery has made
    /// the durable stream tails authoritative. This runs once before the
    /// listener accepts requests.
    pub async fn resume(self: &Arc<Self>, store: Arc<Store>) -> io::Result<()> {
        let now = unix_millis();
        let (scheduled, leases) = {
            let mut state = self.state.lock().await;
            let mut scheduled = Vec::new();
            let mut leases = Vec::new();
            let wake_paths = state.wake_streams.keys().cloned().collect::<HashSet<_>>();
            let roots = state
                .subscriptions
                .values()
                .map(|subscription| subscription.stream_root.clone())
                .collect::<HashSet<_>>();
            let streams_by_root = roots
                .into_iter()
                .map(|root| {
                    let streams = list_streams(&store, &root);
                    (root, streams)
                })
                .collect::<HashMap<_, _>>();
            // A stream append becomes durable before its derived subscription
            // snapshot is fsynced. Reconcile recovered inventory against every
            // pattern so a crash in that narrow window replays at least once
            // instead of losing the stream forever.
            for subscription in state.subscriptions.values_mut() {
                let Some(streams) = streams_by_root.get(&subscription.stream_root) else {
                    continue;
                };
                let pattern = subscription.config.pattern.clone();
                let mut incarnation_changed = false;
                for (path, link) in &mut subscription.streams {
                    match live_stream_metadata(&store, &subscription.stream_root, path) {
                        Some((current_id, _)) => {
                            link.glob = pattern
                                .as_deref()
                                .is_some_and(|pattern| glob_match(pattern, path));
                            // `None` is a state-v1 migration: learn the identity
                            // without replaying. A known mismatch is a new stream
                            // incarnation and must restart at the beginning.
                            if link.stream_id.is_some_and(|old_id| old_id != current_id) {
                                link.acked_offset = BEFORE_FIRST_OFFSET.to_string();
                                incarnation_changed = true;
                            }
                            link.stream_id = Some(current_id);
                        }
                        None => {
                            link.glob = false;
                            if link.explicit {
                                // Explicit membership survives deletion, but a
                                // later recreation has a fresh offset space.
                                link.acked_offset = BEFORE_FIRST_OFFSET.to_string();
                            }
                            if link.stream_id.take().is_some() {
                                incarnation_changed = true;
                            }
                        }
                    }
                }
                subscription
                    .streams
                    .retain(|_, link| link.explicit || link.glob);
                if incarnation_changed {
                    // Fence any recovered holder/callback whose snapshot named
                    // a deleted or replaced stream incarnation. The pending scan
                    // below will mint a fresh generation when work remains.
                    clear_wake(subscription);
                }
                let Some(pattern) = pattern.as_deref() else {
                    continue;
                };
                for stream in streams {
                    if wake_paths.contains(&absolute_stream_path(&subscription.stream_root, stream))
                        || subscription.config.wake_stream.as_deref() == Some(stream.as_str())
                        || !glob_match(pattern, stream)
                        || subscription.streams.contains_key(stream)
                    {
                        continue;
                    }
                    if subscription.streams.len() >= MAX_STREAMS_PER_SUBSCRIPTION {
                        tracing::warn!(
                            subscription_id = subscription.id,
                            stream,
                            "subscription stream limit reached during restart reconciliation"
                        );
                        continue;
                    }
                    subscription.streams.insert(
                        stream.clone(),
                        StreamLink {
                            explicit: false,
                            glob: true,
                            acked_offset: BEFORE_FIRST_OFFSET.to_string(),
                            stream_id: live_stream_metadata(
                                &store,
                                &subscription.stream_root,
                                stream,
                            )
                            .map(|(id, _)| id),
                        },
                    );
                }
            }
            for (key, subscription) in state.subscriptions.iter_mut() {
                if let Some(wake_id) = subscription.wake_id.clone() {
                    if let Some(expires_at_ms) = subscription.lease_expires_at_ms {
                        if expires_at_ms > now {
                            leases.push((
                                key.clone(),
                                subscription.generation,
                                wake_id,
                                subscription.lease_nonce,
                                expires_at_ms,
                            ));
                            if subscription.config.kind == SubscriptionKind::Webhook
                                && subscription.wake_delivery_pending
                            {
                                if let Some(delivery) = current_delivery(subscription, &store) {
                                    scheduled.push((
                                        delivery,
                                        subscription.next_attempt_at_ms.unwrap_or(now),
                                    ));
                                }
                            }
                            continue;
                        }
                        clear_wake(subscription);
                        if has_pending_work(subscription, &store) {
                            let triggered = first_pending(subscription, &store);
                            let delivery = self.create_wake(subscription, &store, triggered);
                            scheduled.push((delivery, now));
                        }
                        continue;
                    }
                    if subscription.wake_delivery_pending {
                        if let Some(delivery) = current_delivery(subscription, &store) {
                            scheduled
                                .push((delivery, subscription.next_attempt_at_ms.unwrap_or(now)));
                        }
                    } else if subscription.config.kind == SubscriptionKind::Webhook {
                        // A delivered webhook that is awaiting async callback
                        // always has a lease. Recover conservatively from an
                        // incomplete/corrupt transition by replaying the same
                        // fenced wake rather than dropping it.
                        subscription.wake_delivery_pending = true;
                        if let Some(delivery) = current_delivery(subscription, &store) {
                            scheduled.push((delivery, now));
                        }
                    }
                } else if has_pending_work(subscription, &store) {
                    let triggered = first_pending(subscription, &store);
                    let delivery = self.create_wake(subscription, &store, triggered);
                    scheduled.push((delivery, now));
                }
            }
            self.persist_state(&state)?;
            (scheduled, leases)
        };
        for lease in leases {
            self.spawn_lease_expiry(store.clone(), lease);
        }
        for (delivery, attempt_at_ms) in scheduled {
            if attempt_at_ms <= unix_millis() {
                self.execute_delivery(store.clone(), delivery).await;
                continue;
            }
            let manager = Arc::clone(self);
            let store = store.clone();
            tokio::spawn(async move {
                sleep_until_unix_ms(attempt_at_ms).await;
                manager.execute_delivery(store, delivery).await;
            });
        }
        Ok(())
    }

    async fn handle_create(
        &self,
        store: Arc<Store>,
        req: Req,
        stream_root: String,
        id: String,
    ) -> Resp {
        // Reserve the append fast-path counter before any source-tail sample.
        // Early returns and cancellation release it; a successful new create
        // converts this reservation into the committed subscription count.
        let mut create_guard = SubscriptionCreateGuard::new(&self.subscription_count);
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
            if let Err(message) = validate_wake_stream(&store, &stream_root, &config).await {
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
            next_attempt_at_ms: None,
            lease_expires_at_ms: None,
            wake_trigger: None,
            wake_delivery_pending: false,
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
                    stream_id: live_stream_metadata(&store, &subscription.stream_root, stream)
                        .map(|(id, _)| id),
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
                    let stream_id =
                        live_stream_metadata(&store, &subscription.stream_root, &stream)
                            .map(|(id, _)| id);
                    let link = subscription.streams.entry(stream).or_insert(StreamLink {
                        explicit: false,
                        glob: false,
                        acked_offset: tail,
                        stream_id,
                    });
                    link.glob = true;
                }
            }
        }
        let body = self.serialize(&subscription, &store);
        let rollback_subscriptions = subscription
            .config
            .wake_stream
            .as_deref()
            .map(|wake_stream| {
                let absolute = absolute_stream_path(&subscription.stream_root, wake_stream);
                state
                    .subscriptions
                    .iter()
                    .filter_map(|(key, existing)| {
                        let relative = relative_stream_path(&existing.stream_root, &absolute)?;
                        existing
                            .streams
                            .contains_key(&relative)
                            .then(|| (key.clone(), existing.clone()))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        register_wake_stream(&mut state, &subscription, &store);
        state
            .subscriptions
            .insert(subscription_key.clone(), subscription);
        if !self.persist_state_for_request(&state) {
            let subscription = state
                .subscriptions
                .remove(&subscription_key)
                .expect("new subscription inserted");
            unregister_wake_stream(&mut state, &subscription);
            for (key, existing) in rollback_subscriptions {
                state.subscriptions.insert(key, existing);
            }
            return internal_subscription_error();
        }
        create_guard.commit();
        json_response(201, body)
    }

    async fn handle_claim(
        self: &Arc<Self>,
        store: Arc<Store>,
        req: Req,
        stream_root: String,
        id: String,
    ) -> Resp {
        match self.service_jwt.verify(bearer_token(&req)).await {
            Ok(()) => {}
            Err(ServiceJwtError::Unavailable) => {
                return subscription_error(
                    503,
                    "SERVICE_JWT_NOT_CONFIGURED",
                    "Pull-wake claims require service-JWT verification",
                )
            }
            Err(ServiceJwtError::Missing) => {
                return subscription_error(
                    401,
                    "SERVICE_JWT_REQUIRED",
                    "Missing service JWT Authorization header",
                )
            }
            Err(ServiceJwtError::Invalid) => {
                return subscription_error(401, "SERVICE_JWT_INVALID", "Service JWT is invalid")
            }
            Err(ServiceJwtError::Forbidden) => {
                return subscription_error(
                    403,
                    "SERVICE_JWT_FORBIDDEN",
                    "Service JWT does not grant the required scope",
                )
            }
        }
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
        let (response, lease) = {
            let mut state = self.state.lock().await;
            let key = subscription_key(&stream_root, &id);
            let Some(subscription) = state.subscriptions.get_mut(&key) else {
                return subscription_error(404, "SUBSCRIPTION_NOT_FOUND", "Subscription not found");
            };
            if subscription.config.kind != SubscriptionKind::PullWake {
                return subscription_error(400, "INVALID_REQUEST", "Subscription is not pull-wake");
            }
            if subscription.holder.is_some()
                && subscription
                    .lease_expires_at_ms
                    .is_some_and(|deadline| deadline <= unix_millis())
            {
                // Do not depend on a delayed timer task to make an expired
                // durable lease reclaimable.
                clear_wake(subscription);
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
            let before = subscription.clone();
            if subscription.wake_id.is_none() {
                // The claimant already has direct evidence of this generation,
                // so no wake-stream notification is needed for this transition.
                let _ = self.create_wake(subscription, &store, first_pending(subscription, &store));
            }
            subscription.holder = Some(claim.worker);
            let token = self.generate_token(
                &subscription_key(&subscription.stream_root, &subscription.id),
                subscription.generation,
            );
            subscription.token = Some(token.clone());
            subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
            subscription.wake_delivery_pending = false;
            subscription.next_attempt_at_ms = None;
            subscription.status = SubscriptionStatus::Active;
            subscription.retry_count = 0;
            let lease_expires_at_ms =
                unix_millis().saturating_add(subscription.config.lease_ttl_ms);
            subscription.lease_expires_at_ms = Some(lease_expires_at_ms);
            let lease = (
                subscription_key(&subscription.stream_root, &subscription.id),
                subscription.generation,
                subscription.wake_id.clone().unwrap_or_default(),
                subscription.lease_nonce,
                lease_expires_at_ms,
            );
            let streams = stream_infos_json(subscription, &store, true);
            let result = (
                json!({
                    "wake_id": subscription.wake_id,
                    "generation": subscription.generation,
                    "token": token,
                    "streams": streams,
                    "lease_ttl_ms": subscription.config.lease_ttl_ms
                }),
                lease,
            );
            if !self.persist_state_for_request(&state) {
                state.subscriptions.insert(key, before);
                return internal_subscription_error();
            }
            result
        };
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
            let before = subscription.clone();
            if let Err(message) = apply_acks(subscription, &request, &store) {
                return subscription_error(409, "INVALID_OFFSET", message);
            }

            let mut delivery = None;
            let mut lease = None;
            let mut next_wake = false;
            if request.done == Some(true) {
                // Pull/callback completion applies only explicit `acks`.
                // Omitted snapshot streams remain pending for the next wake.
                clear_wake(subscription);
                if has_pending_work(subscription, &store) {
                    let triggered = first_pending(subscription, &store);
                    delivery = Some(self.create_wake(subscription, &store, triggered));
                    next_wake = true;
                }
            } else {
                subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
                subscription.wake_delivery_pending = false;
                subscription.next_attempt_at_ms = None;
                subscription.status = SubscriptionStatus::Active;
                subscription.retry_count = 0;
                let lease_expires_at_ms =
                    unix_millis().saturating_add(subscription.config.lease_ttl_ms);
                subscription.lease_expires_at_ms = Some(lease_expires_at_ms);
                lease = Some((
                    key.clone(),
                    subscription.generation,
                    subscription.wake_id.clone().unwrap_or_default(),
                    subscription.lease_nonce,
                    lease_expires_at_ms,
                ));
            }
            let result = (json!({"ok": true, "next_wake": next_wake}), delivery, lease);
            if !self.persist_state_for_request(&state) {
                state.subscriptions.insert(key.clone(), before);
                return internal_subscription_error();
            }
            result
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
            let before = subscription.clone();
            clear_wake(subscription);
            let delivery = if has_pending_work(subscription, &store) {
                let triggered = first_pending(subscription, &store);
                Some(self.create_wake(subscription, &store, triggered))
            } else {
                None
            };
            if !self.persist_state_for_request(&state) {
                state.subscriptions.insert(key.clone(), before);
                return internal_subscription_error();
            }
            delivery
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
            let mut changed = false;
            for subscription in state.subscriptions.values_mut() {
                let Some(relative) = relative_stream_path(&subscription.stream_root, absolute_path)
                else {
                    continue;
                };
                let current_id = live_stream_metadata(&store, &subscription.stream_root, &relative)
                    .map(|(id, _)| id);
                let replaced = subscription.streams.get_mut(&relative).is_some_and(|link| {
                    let replaced = link.stream_id.is_some() && link.stream_id != current_id;
                    if replaced {
                        link.acked_offset = BEFORE_FIRST_OFFSET.to_string();
                    }
                    link.stream_id = current_id;
                    replaced
                });
                if replaced {
                    // Explicit and glob links share incarnation fencing. Lazy
                    // TTL expiry bypasses `on_stream_deleted`, so the first
                    // append to a recreated path must invalidate the old wake.
                    subscription.wake_snapshot.remove(&relative);
                    clear_wake(subscription);
                    changed = true;
                }
                if subscription
                    .config
                    .pattern
                    .as_deref()
                    .is_some_and(|pattern| glob_match(pattern, &relative))
                {
                    if !subscription.streams.contains_key(&relative)
                        && subscription.streams.len() >= MAX_STREAMS_PER_SUBSCRIPTION
                    {
                        changed |= prune_stale_glob_links(subscription, &store);
                        if subscription.streams.len() >= MAX_STREAMS_PER_SUBSCRIPTION {
                            tracing::warn!(
                                subscription_id = subscription.id,
                                stream = relative,
                                "subscription stream limit reached; glob match not linked"
                            );
                            continue;
                        }
                    }
                    let link = subscription
                        .streams
                        .entry(relative.clone())
                        .or_insert(StreamLink {
                            explicit: false,
                            glob: false,
                            acked_offset: BEFORE_FIRST_OFFSET.to_string(),
                            stream_id: current_id,
                        });
                    link.stream_id = current_id;
                    changed |= !link.glob;
                    link.glob = true;
                }
                if subscription.streams.contains_key(&relative)
                    && subscription.wake_id.is_none()
                    && subscription.holder.is_none()
                    && has_pending_work(subscription, &store)
                {
                    deliveries.push(self.create_wake(subscription, &store, relative.clone()));
                    changed = true;
                }
            }
            if changed {
                // Source durability is authoritative. Persist this derived
                // wake/link transition on the coalescing writer so an append
                // never deep-serializes and fsyncs all subscriptions while
                // holding the global mutex. Restart reconciliation rebuilds a
                // wake if the process exits before this snapshot lands.
                self.schedule_state_persistence();
            }
            deliveries
        };
        for delivery in deliveries {
            self.execute_delivery(store.clone(), delivery).await;
        }
    }

    /// Durably apply the subscription-side transition for one retired stream
    /// incarnation. The caller keeps the old, fenced stream mapped until this
    /// returns, so `expected_stream_id` prevents a delayed retry from mutating
    /// links belonging to a replacement at the same path.
    pub async fn on_stream_deleted(
        self: &Arc<Self>,
        store: Arc<Store>,
        absolute_path: &str,
        expected_stream_id: u64,
    ) -> io::Result<()> {
        if self.subscription_count.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        if store
            .streams
            .get(absolute_path)
            .is_some_and(|stream| stream.id != expected_stream_id)
        {
            return Ok(());
        }
        let deliveries = {
            let mut state = self.state.lock().await;
            // Identify affected subscriptions before cloning any rollback
            // state. The overwhelmingly common deletion has no matching link;
            // it must stay allocation- and persistence-free.
            let affected = state
                .subscriptions
                .iter()
                .filter_map(|(key, subscription)| {
                    let relative = relative_stream_path(&subscription.stream_root, absolute_path)?;
                    let linked = subscription
                        .streams
                        .get(&relative)
                        .is_some_and(|link| link.stream_id == Some(expected_stream_id));
                    let wake_stream =
                        subscription.config.wake_stream.as_deref() == Some(relative.as_str());
                    (linked || wake_stream).then(|| (key.clone(), relative))
                })
                .collect::<Vec<_>>();
            if affected.is_empty() {
                return Ok(());
            }
            let before = affected
                .iter()
                .map(|(key, _)| {
                    (
                        key.clone(),
                        state
                            .subscriptions
                            .get(key)
                            .expect("affected subscription still exists")
                            .clone(),
                    )
                })
                .collect::<Vec<_>>();
            let mut deliveries = Vec::new();
            for (key, relative) in &affected {
                let subscription = state
                    .subscriptions
                    .get_mut(key)
                    .expect("affected subscription still exists");
                let was_linked = subscription
                    .streams
                    .get(relative)
                    .is_some_and(|link| link.stream_id == Some(expected_stream_id));
                let was_wake_stream =
                    subscription.config.wake_stream.as_deref() == Some(relative.as_str());
                let mut remove_link = false;
                if let Some(link) = subscription
                    .streams
                    .get_mut(relative)
                    .filter(|_| was_linked)
                {
                    if link.explicit {
                        // Explicit membership survives deletion/recreation, but
                        // the recreated stream starts a new offset lifetime.
                        link.glob = false;
                        link.acked_offset = BEFORE_FIRST_OFFSET.to_string();
                        link.stream_id = None;
                    } else {
                        remove_link = true;
                    }
                }
                let was_in_snapshot = subscription.wake_snapshot.contains_key(relative);
                if remove_link {
                    subscription.streams.remove(relative);
                }
                if (was_wake_stream || was_in_snapshot) && subscription.wake_id.is_some() {
                    // Any worker/callback for the old snapshot could otherwise
                    // acknowledge offsets against a replacement stream at the
                    // same path. Fence it regardless of whether it is claimed.
                    clear_wake(subscription);
                    if has_pending_work(subscription, &store) {
                        let triggered = first_pending(subscription, &store);
                        deliveries.push(self.create_wake(subscription, &store, triggered));
                    }
                } else if subscription.wake_id.is_some()
                    && subscription.holder.is_none()
                    && !has_pending_work(subscription, &store)
                {
                    clear_wake(subscription);
                }
            }
            let persisted = PersistedState {
                version: STATE_VERSION,
                subscriptions: state.subscriptions.values().cloned().collect(),
            };
            let sequence = self
                .persistence_sequence
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1);
            let path = self.state_path.clone();
            let file_lock = Arc::clone(&self.persistence_file_lock);
            let persisted_sequence = Arc::clone(&self.persisted_sequence);
            let result = tokio::task::spawn_blocking(move || {
                persist_ordered_snapshot(
                    &path,
                    &file_lock,
                    &persisted_sequence,
                    sequence,
                    &persisted,
                )
            })
            .await
            .map_err(|error| io::Error::other(format!("subscription writer failed: {error}")))
            .and_then(|result| result);
            if let Err(error) = result {
                for (key, subscription) in before {
                    state.subscriptions.insert(key, subscription);
                }
                return Err(error);
            }
            deliveries
        };
        for delivery in deliveries {
            self.execute_delivery(store.clone(), delivery).await;
        }
        Ok(())
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
        subscription.status = SubscriptionStatus::Active;
        subscription.retry_count = 0;
        subscription.next_attempt_at_ms = None;
        subscription.lease_expires_at_ms = None;
        subscription.wake_trigger = Some(triggered_by.clone());
        subscription.wake_delivery_pending = true;
        subscription.lease_nonce = subscription.lease_nonce.wrapping_add(1);
        let nonce = subscription.lease_nonce;
        match subscription.config.kind {
            SubscriptionKind::Webhook => {
                let key = subscription_key(&subscription.stream_root, &subscription.id);
                subscription.token = Some(self.generate_token(&key, subscription.generation));
                // PROTOCOL §7.3: webhook leases begin when the wake is issued,
                // not when the endpoint accepts delivery.
                subscription.lease_expires_at_ms =
                    Some(unix_millis().saturating_add(subscription.config.lease_ttl_ms));
                Delivery::Webhook {
                    key,
                    generation: subscription.generation,
                    wake_id,
                    nonce,
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
                    nonce,
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
                    nonce,
                } => {
                    let current = {
                        let state = self.state.lock().await;
                        state.subscriptions.get(&key).is_some_and(|subscription| {
                            subscription.generation == generation
                                && subscription.wake_id.as_deref() == Some(wake_id.as_str())
                                && subscription.wake_delivery_pending
                                && subscription.lease_nonce == nonce
                        })
                    };
                    if !current {
                        return;
                    }
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
                                && subscription.lease_nonce == nonce
                                && subscription.wake_delivery_pending
                            {
                                subscription.status = SubscriptionStatus::Active;
                                subscription.retry_count = 0;
                                subscription.next_attempt_at_ms = None;
                                subscription.wake_delivery_pending = false;
                            }
                        }
                        self.persist_background_or_abort(&state, "delivered pull wake");
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
                                nonce,
                            },
                        )
                        .await;
                    }
                }
                Delivery::Webhook {
                    key,
                    generation,
                    wake_id,
                    nonce,
                } => {
                    let lease = {
                        let state = self.state.lock().await;
                        let Some(subscription) = state.subscriptions.get(&key) else {
                            return;
                        };
                        if subscription.generation != generation
                            || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                            || subscription.lease_nonce != nonce
                            || !subscription.wake_delivery_pending
                        {
                            return;
                        }
                        subscription.lease_expires_at_ms.map(|expires_at_ms| {
                            (
                                key.clone(),
                                generation,
                                wake_id.clone(),
                                nonce,
                                expires_at_ms,
                            )
                        })
                    };
                    if let Some(lease) = lease {
                        self.spawn_lease_expiry(store.clone(), lease);
                    }
                    let manager = Arc::clone(self);
                    tokio::spawn(async move {
                        manager
                            .deliver_webhook(store, key, generation, wake_id, nonce)
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
        nonce: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let (url, body) = {
                let state = self.state.lock().await;
                let Some(subscription) = state.subscriptions.get(&key) else {
                    return;
                };
                if subscription.generation != generation
                    || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                    || subscription.lease_nonce != nonce
                    || !subscription.wake_delivery_pending
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
            let (kid, signature) = match self.sign_webhook(format!("{timestamp}.{body}").as_bytes())
            {
                Ok(signature) => signature,
                Err(error) => {
                    tracing::error!(%error, "failed to sign subscription webhook");
                    self.schedule_webhook_retry(store, key, generation, wake_id, nonce)
                        .await;
                    return;
                }
            };
            let signature = format!("t={timestamp},kid={},ed25519={}", kid, signature);
            let response = send_pinned_webhook(&url, signature, body).await;

            let done = match response {
                Ok(response) if response.status().is_success() => {
                    match bounded_webhook_done(response).await {
                        Ok(done) => done,
                        Err(error) => {
                            tracing::warn!(%error, "subscription webhook response rejected");
                            self.schedule_webhook_retry(store, key, generation, wake_id, nonce)
                                .await;
                            return;
                        }
                    }
                }
                Ok(response) => {
                    tracing::warn!(status = %response.status(), "subscription webhook rejected delivery");
                    self.schedule_webhook_retry(store, key, generation, wake_id, nonce)
                        .await;
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, "subscription webhook delivery failed");
                    self.schedule_webhook_retry(store, key, generation, wake_id, nonce)
                        .await;
                    return;
                }
            };

            let delivery = {
                let mut state = self.state.lock().await;
                let Some(subscription) = state.subscriptions.get_mut(&key) else {
                    return;
                };
                if subscription.generation != generation
                    || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                    || subscription.lease_nonce != nonce
                    || !subscription.wake_delivery_pending
                {
                    return;
                }
                subscription.status = SubscriptionStatus::Active;
                subscription.retry_count = 0;
                subscription.next_attempt_at_ms = None;
                subscription.wake_delivery_pending = false;
                let result = if !done {
                    None
                } else {
                    acknowledge_wake_snapshot(subscription);
                    clear_wake(subscription);
                    if has_pending_work(subscription, &store) {
                        let triggered = first_pending(subscription, &store);
                        Some(self.create_wake(subscription, &store, triggered))
                    } else {
                        None
                    }
                };
                self.persist_background_or_abort(&state, "webhook delivery result");
                result
            };
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
        nonce: u64,
    ) {
        let attempt_at_ms = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state.subscriptions.get_mut(&key) else {
                return;
            };
            if subscription.generation != generation
                || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                || subscription.lease_nonce != nonce
                || !subscription.wake_delivery_pending
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
            let delay = base.saturating_mul(jitter) / 100;
            let attempt_at_ms = unix_millis().saturating_add(delay);
            subscription.next_attempt_at_ms = Some(attempt_at_ms);
            subscription.wake_delivery_pending = true;
            self.persist_background_or_abort(&state, "webhook retry schedule");
            attempt_at_ms
        };
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            sleep_until_unix_ms(attempt_at_ms).await;
            manager
                .deliver_webhook(store, key, generation, wake_id, nonce)
                .await;
        });
    }

    async fn schedule_pull_wake_retry(self: &Arc<Self>, store: Arc<Store>, delivery: Delivery) {
        let Delivery::PullWake {
            key,
            generation,
            wake_id,
            nonce,
            ..
        } = &delivery
        else {
            return;
        };
        let key = key.clone();
        let generation = *generation;
        let wake_id = wake_id.clone();
        let nonce = *nonce;
        let attempt_at_ms = {
            let mut state = self.state.lock().await;
            let Some(subscription) = state.subscriptions.get_mut(&key) else {
                return;
            };
            if subscription.generation != generation
                || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                || subscription.lease_nonce != nonce
                || !subscription.wake_delivery_pending
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
            let delay = base.saturating_mul(jitter) / 100;
            let attempt_at_ms = unix_millis().saturating_add(delay);
            subscription.next_attempt_at_ms = Some(attempt_at_ms);
            subscription.wake_delivery_pending = true;
            self.persist_background_or_abort(&state, "pull-wake retry schedule");
            attempt_at_ms
        };
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            sleep_until_unix_ms(attempt_at_ms).await;
            let current = {
                let state = manager.state.lock().await;
                state.subscriptions.get(&key).is_some_and(|subscription| {
                    subscription.generation == generation
                        && subscription.wake_id.as_deref() == Some(wake_id.as_str())
                        && subscription.lease_nonce == nonce
                        && subscription.wake_delivery_pending
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
            let (id, generation, wake_id, nonce, expires_at_ms) = lease;
            sleep_until_unix_ms(expires_at_ms).await;
            let delivery = {
                let mut state = manager.state.lock().await;
                let Some(subscription) = state.subscriptions.get_mut(&id) else {
                    return;
                };
                if subscription.generation != generation
                    || subscription.wake_id.as_deref() != Some(wake_id.as_str())
                    || subscription.lease_nonce != nonce
                    || subscription.lease_expires_at_ms != Some(expires_at_ms)
                {
                    return;
                }
                clear_wake(subscription);
                let delivery = if has_pending_work(subscription, &store) {
                    let triggered = first_pending(subscription, &store);
                    Some(manager.create_wake(subscription, &store, triggered))
                } else {
                    None
                };
                manager.persist_background_or_abort(&state, "lease expiry");
                delivery
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
            let (signing_kid, _) = self.active_signing_metadata();
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
                        "kid": signing_kid,
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

fn current_delivery(subscription: &Subscription, store: &Store) -> Option<Delivery> {
    let wake_id = subscription.wake_id.clone()?;
    let key = subscription_key(&subscription.stream_root, &subscription.id);
    match subscription.config.kind {
        SubscriptionKind::Webhook => Some(Delivery::Webhook {
            key,
            generation: subscription.generation,
            wake_id,
            nonce: subscription.lease_nonce,
        }),
        SubscriptionKind::PullWake => Some(Delivery::PullWake {
            key,
            id: subscription.id.clone(),
            stream_root: subscription.stream_root.clone(),
            wake_stream: subscription.config.wake_stream.clone()?,
            stream: subscription
                .wake_trigger
                .clone()
                .unwrap_or_else(|| first_pending(subscription, store)),
            generation: subscription.generation,
            wake_id,
            nonce: subscription.lease_nonce,
        }),
    }
}

fn acknowledge_wake_snapshot(subscription: &mut Subscription) {
    for (path, tail) in subscription.wake_snapshot.clone() {
        if let Some(link) = subscription.streams.get_mut(&path) {
            if tail.as_str() > link.acked_offset.as_str() {
                link.acked_offset = tail;
            }
        }
    }
}

fn create_secure_dir(path: &Path) -> io::Result<()> {
    let existed = path.exists();
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    if !existed {
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

fn persist_ordered_snapshot(
    path: &Path,
    file_lock: &StdMutex<()>,
    persisted_sequence: &AtomicU64,
    sequence: u64,
    snapshot: &PersistedState,
) -> io::Result<()> {
    let _writer = file_lock.lock().unwrap_or_else(|error| error.into_inner());
    if sequence <= persisted_sequence.load(Ordering::Acquire) {
        return Ok(());
    }
    atomic_write_json(path, snapshot)?;
    persisted_sequence.store(sequence, Ordering::Release);
    Ok(())
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent"))?;
    create_secure_dir(parent)?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    // Once rename succeeds, the new snapshot is visible and it is no longer
    // safe for callers to roll memory back to the old snapshot. A directory
    // fsync failure makes crash outcome indeterminate, so fail-stop exactly as
    // the WAL durability barriers do rather than continue with split truth.
    if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
        eprintln!(
            "fatal: subscription snapshot rename succeeded but parent fsync failed for {}: {error}",
            path.display()
        );
        std::process::abort();
    }
    Ok(())
}

fn load_persisted_state(path: &Path) -> io::Result<ManagerState> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ManagerState::default()),
        Err(error) => return Err(error),
    };
    let persisted: PersistedState = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("corrupt subscription state {}: {error}", path.display()),
        )
    })?;
    if persisted.version != STATE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported subscription state version {} in {}",
                persisted.version,
                path.display()
            ),
        ));
    }
    if persisted.subscriptions.len() > MAX_SUBSCRIPTIONS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persisted subscription count exceeds the configured safety limit",
        ));
    }
    let mut subscriptions = HashMap::with_capacity(persisted.subscriptions.len());
    for mut subscription in persisted.subscriptions {
        if !valid_subscription_id(&subscription.id)
            || subscription.streams.len() > MAX_STREAMS_PER_SUBSCRIPTION
            || subscription
                .streams
                .keys()
                .any(|path| !valid_relative_stream_path(path))
            || subscription
                .config
                .webhook_url
                .as_deref()
                .is_some_and(|url| validate_webhook_url(url).is_err())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted subscription state failed validation",
            ));
        }
        if subscription.wake_id.is_none() {
            clear_wake(&mut subscription);
        }
        let key = subscription_key(&subscription.stream_root, &subscription.id);
        if subscriptions.insert(key, subscription).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted subscription state contains duplicate identities",
            ));
        }
    }
    Ok(ManagerState {
        subscriptions,
        wake_streams: HashMap::new(),
    })
}

fn load_or_create_secrets(
    path: &Path,
    rng: &SystemRandom,
) -> io::Result<(SigningKeyRing, [u8; 32])> {
    if let Some(loaded) = load_secrets(path)? {
        return Ok(loaded);
    }

    let mut token_secret = [0u8; 32];
    rng.fill(&mut token_secret)
        .map_err(|_| io::Error::other("failed to generate callback token key"))?;
    let key = generate_signing_key(rng, unix_millis())?;
    let active_kid = key.persisted.kid.clone();
    let keyring = SigningKeyRing {
        active_kid,
        keys: vec![key],
    };
    persist_secrets(path, &keyring, &token_secret)?;
    Ok((keyring, token_secret))
}

/// Read an existing secret bundle without ever creating or replacing it.
fn load_secrets(path: &Path) -> io::Result<Option<(SigningKeyRing, [u8; 32])>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    {
        let persisted: PersistedSecrets = serde_json::from_slice(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("corrupt subscription secrets {}: {error}", path.display()),
            )
        })?;
        if persisted.version != SECRETS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported subscription secrets version {}",
                    persisted.version
                ),
            ));
        }
        let token_bytes = hex_decode(&persisted.token_secret).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid callback token secret")
        })?;
        let token_secret: [u8; 32] = token_bytes.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "callback token secret must contain exactly 32 bytes",
            )
        })?;
        let mut keys = Vec::with_capacity(persisted.signing_keys.len());
        for persisted_key in persisted.signing_keys {
            let pkcs8 = hex_decode(&persisted_key.pkcs8).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid webhook signing key")
            })?;
            let pair = Arc::new(Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid webhook signing key")
            })?);
            let (kid, x) = signing_identity(&pair);
            if kid != persisted_key.kid || x != persisted_key.x {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "webhook signing key identity does not match its private key",
                ));
            }
            keys.push(SigningKeyEntry {
                pair,
                // After restart, conservatively wait a complete advertised
                // JWKS cache interval again before activating a pending key.
                activate_not_before: persisted_key
                    .activate_after_ms
                    .map(|_| Instant::now() + Duration::from_secs(JWKS_CACHE_MAX_AGE_SECS)),
                persisted: persisted_key,
            });
        }
        if keys.is_empty()
            || !keys
                .iter()
                .any(|key| key.persisted.kid == persisted.active_kid)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "webhook signing keyring has no active key",
            ));
        }
        Ok(Some((
            SigningKeyRing {
                active_kid: persisted.active_kid,
                keys,
            },
            token_secret,
        )))
    }
}

fn clone_signing_key_ring(keys: &SigningKeyRing) -> SigningKeyRing {
    keys.clone()
}

fn persist_secrets(path: &Path, keys: &SigningKeyRing, token_secret: &[u8; 32]) -> io::Result<()> {
    atomic_write_json(
        path,
        &PersistedSecrets {
            version: SECRETS_VERSION,
            token_secret: hex_encode(token_secret),
            active_kid: keys.active_kid.clone(),
            signing_keys: keys.keys.iter().map(|key| key.persisted.clone()).collect(),
        },
    )
}

fn generate_signing_key(rng: &SystemRandom, created_at_ms: u64) -> io::Result<SigningKeyEntry> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng)
        .map_err(|_| io::Error::other("failed to generate webhook signing key"))?;
    let pair = Arc::new(
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| io::Error::other("failed to parse webhook signing key"))?,
    );
    let (kid, x) = signing_identity(&pair);
    Ok(SigningKeyEntry {
        pair,
        activate_not_before: None,
        persisted: PersistedSigningKey {
            pkcs8: hex_encode(pkcs8.as_ref()),
            kid,
            x,
            created_at_ms,
            retire_after_ms: None,
            activate_after_ms: None,
        },
    })
}

fn signing_identity(pair: &Ed25519KeyPair) -> (String, String) {
    let x = base64_encode(pair.public_key().as_ref(), BASE64_URL, false);
    let thumbprint = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    let kid = format!(
        "ds_{}",
        base64_encode(
            digest(&SHA256, thumbprint.as_bytes()).as_ref(),
            BASE64_URL,
            false
        )
    );
    (kid, x)
}

fn rotate_signing_keys_if_due(
    keys: &mut SigningKeyRing,
    rng: &SystemRandom,
    rotation_ms: u64,
    replay_window_ms: u64,
) -> io::Result<bool> {
    let now = unix_millis();
    let original_len = keys.keys.len();
    let active_kid = keys.active_kid.clone();
    keys.keys.retain(|key| {
        key.persisted.kid == active_kid
            || key.persisted.activate_after_ms.is_some()
            || key
                .persisted
                .retire_after_ms
                .is_some_and(|retire_after| retire_after > now)
    });
    let mut changed = keys.keys.len() != original_len;
    if let Some(pending_index) = keys.keys.iter().position(|key| {
        key.persisted
            .activate_after_ms
            .is_some_and(|activate_after| activate_after <= now)
            && key
                .activate_not_before
                .map_or(true, |activate_after| Instant::now() >= activate_after)
    }) {
        let active_kid = keys.active_kid.clone();
        if let Some(active) = keys
            .keys
            .iter_mut()
            .find(|key| key.persisted.kid == active_kid)
        {
            active.persisted.retire_after_ms = Some(now.saturating_add(replay_window_ms));
        }
        keys.keys[pending_index].persisted.activate_after_ms = None;
        keys.keys[pending_index].activate_not_before = None;
        keys.active_kid = keys.keys[pending_index].persisted.kid.clone();
        changed = true;
    }
    let active_created_at = keys
        .keys
        .iter()
        .find(|key| key.persisted.kid == keys.active_kid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "active signing key missing"))?
        .persisted
        .created_at_ms;
    let has_pending = keys
        .keys
        .iter()
        .any(|key| key.persisted.activate_after_ms.is_some());
    if rotation_ms != 0 && !has_pending && now.saturating_sub(active_created_at) >= rotation_ms {
        let mut new_key = generate_signing_key(rng, now)?;
        new_key.persisted.activate_after_ms =
            Some(now.saturating_add(JWKS_CACHE_MAX_AGE_SECS.saturating_mul(1_000)));
        new_key.activate_not_before =
            Some(Instant::now() + Duration::from_secs(JWKS_CACHE_MAX_AGE_SECS));
        keys.keys.push(new_key);
        changed = true;
    }
    Ok(changed)
}

fn env_seconds(name: &str, default: u64) -> io::Result<u64> {
    match std::env::var(name) {
        Ok(value) => value.parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be an unsigned number of seconds"),
            )
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
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
    validate_webhook_url_with_local_policy(raw, local_webhooks_allowed())
}

fn validate_webhook_url_with_local_policy(
    raw: &str,
    allow_local: bool,
) -> Result<(), &'static str> {
    let url = Url::parse(raw).map_err(|_| "webhook.url must be a valid URL")?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("webhook.url must not include credentials or a fragment");
    }
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
        "http" if allow_local && host == "localhost" => Ok(()),
        "http" if allow_local && matches!(ip, Some(IpAddr::V4(ip)) if ip.octets()[0] == 127) => {
            Ok(())
        }
        "http" => {
            Err("http webhook URLs require DS_WEBHOOK_ALLOW_LOCALHOST=1 and a localhost target")
        }
        "https" if host == "localhost" => {
            Err("localhost webhook URLs must use http for development")
        }
        "https" if matches!(ip, Some(IpAddr::V6(ip)) if !public_ipv6(ip)) => {
            Err("webhook.url must not target private or link-local hosts")
        }
        "https" if matches!(ip, Some(IpAddr::V4(ip)) if private_ipv4(ip)) => {
            Err("webhook.url must not target private or link-local hosts")
        }
        "https" => Ok(()),
        _ => Err("webhook.url must use https"),
    }
}

fn local_webhooks_allowed() -> bool {
    cfg!(test) || std::env::var(ALLOW_LOCAL_WEBHOOKS_ENV).ok().as_deref() == Some("1")
}

async fn send_pinned_webhook(
    raw_url: &str,
    signature: String,
    body: String,
) -> Result<reqwest::Response, String> {
    validate_webhook_url(raw_url).map_err(str::to_string)?;
    let url = Url::parse(raw_url).map_err(|error| error.to_string())?;
    let host = url
        .host_str()
        .ok_or_else(|| "webhook URL has no host".to_string())?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "webhook URL has no usable port".to_string())?;
    let local_development = url.scheme() == "http"
        && (host == "localhost"
            || host
                .parse::<Ipv4Addr>()
                .is_ok_and(|ip| ip.octets()[0] == 127));

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        // A proxy would perform its own DNS resolution and defeat the pinned
        // public address selected below.
        .no_proxy();
    let mut pinned_addresses = Vec::new();
    if host.parse::<IpAddr>().is_err() {
        let mut addresses = tokio::time::timeout(
            WEBHOOK_DNS_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| "webhook DNS resolution timed out".to_string())?
        .map_err(|error| format!("webhook DNS resolution failed: {error}"))?
        .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err("webhook DNS resolution returned no addresses".to_string());
        }
        if addresses.iter().any(|address| {
            if local_development {
                !address.ip().is_loopback()
            } else {
                !public_webhook_ip(address.ip())
            }
        }) {
            return Err("webhook DNS resolved to a private or local address".to_string());
        }
        // reqwest retains the URL hostname for Host and TLS SNI while routing
        // the socket to this already-validated address, closing the DNS
        // rebinding window between validation and connect.
        builder = builder.resolve_to_addrs(&host, &addresses);
        pinned_addresses = addresses;
    }
    let cache_key = format!("{}|{host}|{port}|{pinned_addresses:?}", url.scheme());
    static CLIENTS: OnceLock<StdMutex<HashMap<String, reqwest::Client>>> = OnceLock::new();
    let clients = CLIENTS.get_or_init(|| StdMutex::new(HashMap::new()));
    let cached = {
        let clients = clients.lock().unwrap();
        clients.get(&cache_key).cloned()
    };
    let client = if let Some(client) = cached {
        client
    } else {
        let client = builder
            .build()
            .map_err(|error| format!("failed to build pinned webhook client: {error}"))?;
        let mut clients = clients.lock().unwrap();
        if clients.len() >= MAX_PINNED_WEBHOOK_CLIENTS {
            clients.clear();
        }
        clients.insert(cache_key, client.clone());
        client
    };
    client
        .post(url)
        .header("content-type", "application/json")
        .header("webhook-signature", signature)
        .body(body)
        .send()
        .await
        .map_err(|error| error.to_string())
}

async fn bounded_webhook_done(mut response: reqwest::Response) -> Result<bool, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_WEBHOOK_RESPONSE_BYTES as u64)
    {
        return Err("webhook response exceeds 64 KiB".to_string());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to read webhook response: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_WEBHOOK_RESPONSE_BYTES {
            return Err("webhook response exceeds 64 KiB".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|value| value.get("done").and_then(Value::as_bool))
        == Some(true))
}

fn public_webhook_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !private_ipv4(ip),
        IpAddr::V6(ip) => public_ipv6(ip),
    }
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    // Public unicast is currently allocated from 2000::/3. Keep this policy
    // conservative and explicitly exclude documentation and benchmarking
    // prefixes that are not valid Internet delivery targets.
    octets[0] & 0xe0 == 0x20
        && !(octets[0] == 0x20 && octets[1] == 0x02)
        && !(octets[0] == 0x20
            && octets[1] == 0x01
            && ((octets[2] == 0x00 && octets[3] == 0x00)
                || (octets[2] == 0x0d && octets[3] == 0xb8)
                || (octets[2] == 0x00 && octets[3] == 0x02)))
}

fn private_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 0
        || ip.is_private()
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

async fn validate_wake_stream(
    store: &Arc<Store>,
    stream_root: &str,
    config: &SubscriptionConfig,
) -> Result<(), &'static str> {
    let Some(wake_stream) = config.wake_stream.as_deref() else {
        return Err("pull-wake subscriptions require wake_stream");
    };
    let lookup_now = SystemTime::now();
    let stream = match store.lookup_at(
        &absolute_stream_path(stream_root, wake_stream),
        lookup_now,
        false,
    ) {
        crate::store::StreamLookup::Live(stream) => stream,
        crate::store::StreamLookup::Gone(_) => return Err("wake_stream is deleted"),
        crate::store::StreamLookup::Missing => {
            return Err("wake_stream must be created before the subscription")
        }
        crate::store::StreamLookup::Expired(candidate) => {
            crate::handlers::enqueue_expired_before_not_found(store, &candidate, lookup_now).await;
            return Err("wake_stream must be created before the subscription");
        }
    };
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
        .filter(|entry| {
            !entry.value().is_fenced()
                && !entry.value().is_expired()
                && !entry.value().shared.read().unwrap().soft_deleted
        })
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

fn live_stream_metadata(store: &Store, stream_root: &str, relative: &str) -> Option<(u64, String)> {
    let stream = store
        .streams
        .get(&absolute_stream_path(stream_root, relative))?
        .clone();
    if stream.is_fenced() || stream.is_expired() || stream.shared.read().unwrap().soft_deleted {
        return None;
    }
    Some((stream.id, format_offset(stream.tail().bytes)))
}

fn live_tail_offset(store: &Store, stream_root: &str, relative: &str) -> Option<String> {
    // Subscription scans run under the manager mutex. Do not call Store::get:
    // its lazy TTL path can unlink files and fsync synchronously. Treat an
    // expired stream as absent and leave deletion to the store's normal sweep.
    live_stream_metadata(store, stream_root, relative).map(|(_, tail)| tail)
}

fn prune_stale_glob_links(subscription: &mut Subscription, store: &Store) -> bool {
    let before = subscription.streams.len();
    let root = subscription.stream_root.clone();
    subscription
        .streams
        .retain(|path, link| link.explicit || live_stream_metadata(store, &root, path).is_some());
    before != subscription.streams.len()
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
    let mut updates = BTreeMap::<String, String>::new();
    for ack in acks {
        let stream = normalize_relative_path(
            ack.stream
                .as_deref()
                .or(ack.path.as_deref())
                .unwrap_or_default(),
        );
        if ack.offset == BEFORE_FIRST_OFFSET
            || !matches!(parse_offset(Some(&ack.offset)), Ok(ParsedOffset::At(_)))
        {
            return Err("Ack offset is invalid for the subscription stream");
        }
        updates
            .entry(stream)
            .and_modify(|offset| {
                if ack.offset > *offset {
                    *offset = ack.offset.clone();
                }
            })
            .or_insert_with(|| ack.offset.clone());
    }
    for (stream, offset) in &updates {
        let Some(link) = subscription.streams.get(stream) else {
            return Err("Ack references an unknown subscription stream");
        };
        if offset < &link.acked_offset
            || offset > &tail_offset(store, &subscription.stream_root, stream)
        {
            return Err("Ack offset is invalid for the subscription stream");
        }
    }
    for (stream, offset) in updates {
        subscription
            .streams
            .get_mut(&stream)
            .expect("ack validated")
            .acked_offset = offset;
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
    subscription.next_attempt_at_ms = None;
    subscription.lease_expires_at_ms = None;
    subscription.wake_trigger = None;
    subscription.wake_delivery_pending = false;
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
        response.headers.push((
            "cache-control",
            "public, max-age=300, must-revalidate".to_string(),
        ));
    }
    response.body = Body::Full(Bytes::from(body.to_string()));
    response
}

fn subscription_error(status: u16, code: &'static str, message: &'static str) -> Resp {
    json_response(status, json!({"error": {"code": code, "message": message}}))
}

fn internal_subscription_error() -> Resp {
    subscription_error(
        500,
        "SUBSCRIPTION_STATE_ERROR",
        "Subscription state could not be persisted",
    )
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

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

async fn sleep_until_unix_ms(deadline_ms: u64) {
    loop {
        let now = unix_millis();
        if now >= deadline_ms {
            return;
        }
        tokio::time::sleep(Duration::from_millis((deadline_ms - now).min(1_000))).await;
        // Re-read the wall clock at least once per second. A backward NTP step
        // re-arms instead of expiring early; a forward step is observed within
        // one second instead of waiting out the old monotonic duration.
    }
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
        assert!(
            validate_webhook_url_with_local_policy("http://127.0.0.1:1234/hook", false).is_err()
        );
        assert!(validate_webhook_url("http://127.0.0.1:1234/hook").is_ok());
        assert!(validate_webhook_url("http://localhost:1234/hook").is_ok());
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://100.64.0.5/hook").is_err());
        assert!(validate_webhook_url("https://192.0.0.5/hook").is_err());
        assert!(validate_webhook_url("https://198.18.0.1/hook").is_err());
        assert!(validate_webhook_url("https://224.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://240.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://0.0.0.1/hook").is_err());
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
    fn signing_rotation_persists_the_new_key_and_retains_the_old_replay_key() {
        let rng = SystemRandom::new();
        let old = generate_signing_key(&rng, unix_millis().saturating_sub(10_000)).unwrap();
        let old_kid = old.persisted.kid.clone();
        let mut keys = SigningKeyRing {
            active_kid: old_kid.clone(),
            keys: vec![old],
        };
        assert!(rotate_signing_keys_if_due(&mut keys, &rng, 1_000, 300_000).unwrap());
        assert_eq!(keys.active_kid, old_kid, "new key must be prepublished");
        assert_eq!(keys.keys.len(), 2);
        let pending = keys
            .keys
            .iter_mut()
            .find(|key| key.persisted.kid != old_kid)
            .unwrap();
        pending.persisted.activate_after_ms = Some(0);
        pending.activate_not_before = Some(Instant::now());
        assert!(rotate_signing_keys_if_due(&mut keys, &rng, 1_000, 300_000).unwrap());
        assert_ne!(keys.active_kid, old_kid);
        assert_eq!(keys.keys.len(), 2);
        assert!(keys
            .keys
            .iter()
            .find(|key| key.persisted.kid == old_kid)
            .unwrap()
            .persisted
            .retire_after_ms
            .is_some_and(|retire_after| retire_after > unix_millis()));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let token_secret = [7u8; 32];
        persist_secrets(&path, &keys, &token_secret).unwrap();
        let (reloaded, reloaded_token_secret) = load_or_create_secrets(&path, &rng).unwrap();
        assert_eq!(reloaded.active_kid, keys.active_kid);
        assert_eq!(reloaded.keys.len(), 2);
        assert_eq!(reloaded_token_secret, token_secret);
    }

    #[test]
    fn failed_signing_key_persistence_never_changes_the_live_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = SubscriptionManager::new(dir.path()).unwrap();
        manager.signing_rotation_ms = 1;
        {
            let mut keys = manager.signing_keys.lock().unwrap();
            let active_kid = keys.active_kid.clone();
            keys.keys
                .iter_mut()
                .find(|key| key.persisted.kid == active_kid)
                .unwrap()
                .persisted
                .created_at_ms = 0;
        }
        let before = manager.active_signing_metadata();
        let before_len = manager.signing_keys.lock().unwrap().keys.len();
        // Renaming a regular temp file over this directory must fail before
        // the candidate ring can be installed in memory.
        manager.secrets_path = dir.path().join("subscriptions");
        assert!(manager.refresh_signing_keys().is_err());
        assert_eq!(manager.active_signing_metadata(), before);
        assert_eq!(manager.signing_keys.lock().unwrap().keys.len(), before_len);
    }

    #[test]
    fn an_older_background_snapshot_cannot_overwrite_a_newer_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let file_lock = StdMutex::new(());
        let persisted_sequence = AtomicU64::new(0);
        let newer = PersistedState {
            version: STATE_VERSION,
            subscriptions: Vec::new(),
        };
        let stale = PersistedState {
            version: 999,
            subscriptions: Vec::new(),
        };
        persist_ordered_snapshot(&path, &file_lock, &persisted_sequence, 2, &newer).unwrap();
        persist_ordered_snapshot(&path, &file_lock, &persisted_sequence, 1, &stale).unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(value["version"], STATE_VERSION);
    }

    // Deliberately hold the synchronous writer lock while yielding: the test
    // must prove the async drain observes a writer blocked in spawn_blocking.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn persistence_drain_waits_for_a_held_snapshot_writer() {
        let (store, dir) = test_store("persistence-drain");
        let file_lock = store.subscriptions.persistence_file_lock.lock().unwrap();
        store.subscriptions.schedule_state_persistence();

        let manager = store.subscriptions.clone();
        let drain = tokio::spawn(async move {
            manager.drain_state_persistence().await;
        });
        tokio::task::yield_now().await;
        assert!(
            !drain.is_finished(),
            "drain must wait for the scheduled writer holding an active slot"
        );

        drop(file_lock);
        tokio::time::timeout(Duration::from_secs(1), drain)
            .await
            .expect("drain must finish after the writer is released")
            .unwrap();

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dns_target_policy_accepts_public_ipv6_and_rejects_local_ranges() {
        assert!(public_webhook_ip("2606:4700:4700::1111".parse().unwrap()));
        for ip in [
            "::1",
            "fd00::1",
            "fe80::1",
            "2001::1",
            "2001:db8::1",
            "2002:7f00:1::",
        ] {
            assert!(!public_webhook_ip(ip.parse().unwrap()), "{ip}");
        }
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
    async fn expired_wake_stream_validation_enqueues_retirement() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("expired-wake");
        let mut wake = json_request(Method::Put, "/root/wake/pool", json!([]));
        wake.headers.push(("stream-ttl".into(), "1".into()));
        assert_eq!(handle(store.clone(), wake).await.status, 201);
        let expired = store.streams.get("/root/wake/pool").unwrap().clone();
        expired.shared.write().unwrap().last_access = SystemTime::now() - Duration::from_secs(2);

        let response = handle(
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
        assert_eq!(response.status, 409);
        assert!(
            !expired.file_path.exists(),
            "validation must hand its expired lookup candidate to retirement"
        );

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
    async fn a_delayed_delete_transition_cannot_unlink_a_replacement_incarnation() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("delete-incarnation-fence");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        let old = store.get("/root/events/a").unwrap();
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "streams": ["events/a"],
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );

        // Model path reuse winning before an old asynchronous deletion callback
        // reaches the subscription manager. The callback must be fenced by the
        // deleted stream's immutable id, never by path alone.
        store.streams.remove("/root/events/a");
        create_json_stream(&store, "/root/events/a").await;
        let replacement = store.get("/root/events/a").unwrap();
        assert_ne!(replacement.id, old.id);

        store
            .subscriptions
            .clone()
            .on_stream_deleted(store.clone(), "/root/events/a", old.id)
            .await
            .unwrap();

        let state = store.subscriptions.state.lock().await;
        let link = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap()
            .streams
            .get("events/a")
            .expect("replacement link must survive a stale delete callback");
        assert_eq!(link.stream_id, Some(replacement.id));
        drop(state);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_failed_delete_transition_is_reported_and_rolled_back() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("delete-transition-persist-failure");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        let stream = store.get("/root/events/a").unwrap();
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "streams": ["events/a"],
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );

        std::fs::remove_file(&store.subscriptions.state_path).unwrap();
        std::fs::create_dir(&store.subscriptions.state_path).unwrap();
        assert!(matches!(
            store.prepare_delete(&stream).await,
            crate::store::PrepareRetirement::Ready
        ));
        let error = store
            .subscriptions
            .clone()
            .on_stream_deleted(store.clone(), "/root/events/a", stream.id)
            .await
            .expect_err("the retirement coordinator must see persistence failure");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::IsADirectory
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::Other
            ),
            "unexpected persistence failure: {error}"
        );

        let state = store.subscriptions.state.lock().await;
        let link = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap()
            .streams
            .get("events/a")
            .unwrap();
        assert_eq!(link.stream_id, Some(stream.id));
        drop(state);
        let retry = handle(
            store.clone(),
            json_request(Method::Put, "/root/events/a", json!([])),
        )
        .await;
        assert_eq!(
            retry.status, 503,
            "a compatible PUT must not downgrade a failed explicit retirement"
        );
        assert!(retry
            .headers
            .iter()
            .any(|(name, value)| *name == "retry-after" && value == "1"));
        assert_eq!(
            handle(
                store.clone(),
                Req {
                    method: Method::Get,
                    path: "/root/events/a".into(),
                    query: Some("offset=0000000000000000_0000000000000000".into()),
                    headers: vec![],
                    body: Bytes::new(),
                },
            )
            .await
            .status,
            404
        );
        assert!(
            stream.file_path.exists(),
            "a GET must not downgrade a failed explicit retirement to expiry durability"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delete_transition_persistence_does_not_block_the_async_worker() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("delete-transition-blocking-io");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        let stream = store.streams.get("/root/events/a").unwrap().clone();
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "streams": ["events/a"],
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );

        let file_lock = Arc::clone(&store.subscriptions.persistence_file_lock);
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = file_lock.lock().unwrap();
            locked_tx.send(()).unwrap();
            // The timeout is a deadlock failsafe for the RED implementation,
            // where synchronous fsync blocks this single-thread Tokio runtime.
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        locked_rx.recv().unwrap();

        let manager = store.subscriptions.clone();
        let store2 = store.clone();
        let stream_id = stream.id;
        let transition = tokio::spawn(async move {
            manager
                .on_stream_deleted(store2, "/root/events/a", stream_id)
                .await
        });
        let started = Instant::now();
        tokio::task::yield_now().await;
        let worker_delay = started.elapsed();
        release_tx.send(()).unwrap();
        holder.join().unwrap();

        transition.await.unwrap().unwrap();
        assert!(
            worker_delay < Duration::from_millis(500),
            "subscription fsync blocked the async worker for {worker_delay:?}"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_publication_winner_remains_acked_through_subscription_notification() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("post-full-append-guard");
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
        let stream = store.streams.get("/root/events/a").unwrap().clone();

        // Hold the manager lock so retirement fences after durable publication
        // wins but before the awaited subscription callback completes. The
        // guard keeps retirement from finishing; the visible append stays 2xx.
        let state = store.subscriptions.state.lock().await;
        let append = tokio::spawn(handle(
            store.clone(),
            json_request(Method::Post, "/root/events/a", json!({"value": 1})),
        ));
        while stream.tail().bytes == 0 {
            tokio::task::yield_now().await;
        }
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        assert!(
            !retirement.is_finished(),
            "retirement must wait through subscription notification"
        );
        drop(state);

        assert_eq!(append.await.unwrap().status, 204);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_put_publication_winner_remains_acked_through_subscription_notification() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("put-full-append-guard");
        create_json_stream(&store, "/root/wake/pool").await;
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

        // As above, publication is the winner even though DELETE fences while
        // the initial PUT is still awaiting subscription notification.
        let state = store.subscriptions.state.lock().await;
        let create = tokio::spawn(handle(
            store.clone(),
            json_request(Method::Put, "/root/events/initial", json!({"value": 1})),
        ));
        let stream = loop {
            if let Some(stream) = store.streams.get("/root/events/initial") {
                let stream = stream.clone();
                if stream.tail().bytes > 0 {
                    break stream;
                }
            }
            tokio::task::yield_now().await;
        };
        let store2 = store.clone();
        let stream2 = stream.clone();
        let retirement = tokio::spawn(async move { store2.prepare_delete(&stream2).await });
        while !stream.is_fenced() {
            tokio::task::yield_now().await;
        }
        assert!(
            !retirement.is_finished(),
            "retirement must wait through initial PUT notification"
        );
        drop(state);

        assert_eq!(create.await.unwrap().status, 201);
        assert_eq!(
            retirement.await.unwrap(),
            crate::store::PrepareRetirement::Ready
        );

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deleting_an_explicit_stream_does_not_leave_phantom_pending_work() {
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
    async fn expired_glob_membership_is_pruned_at_the_stream_limit() {
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
                        stream_id: None,
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
            next_attempt_at_ms: None,
            lease_expires_at_ms: None,
            wake_trigger: None,
            wake_delivery_pending: false,
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
        assert_eq!(subscription.streams.len(), 1);
        assert!(subscription.streams.contains_key("overflow"));
        assert!(!subscription.streams.contains_key("existing/0"));
        drop(state);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deleting_and_recreating_a_snapshotted_stream_fences_the_old_worker() {
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
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/c", json!({"value": 1})),
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
            .find(|stream| stream["path"] == "events/c")
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
        create_json_stream(&store, "/root/events/c").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/c", json!({"value": 2})),
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
                "acks": [{"stream": "events/c", "offset": source["tail_offset"]}],
                "done": true
            }),
        );
        ack.headers.push((
            "authorization".into(),
            format!("Bearer {}", claim["token"].as_str().unwrap()),
        ));
        assert_eq!(handle(store.clone(), ack).await.status, 409);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failed_pull_wake_delivery_retries_after_the_wake_stream_returns() {
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
    async fn subscriptions_leases_tokens_and_signing_keys_survive_restart() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("durable-control-state");
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
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let claim = response_json(
            handle(
                store.clone(),
                json_request(
                    Method::Post,
                    "/root/__ds/subscriptions/sub-1/claim",
                    json!({"worker": "worker-a"}),
                ),
            )
            .await,
        );
        let original_jwks = response_json(
            handle(
                store.clone(),
                json_request(Method::Get, "/root/__ds/jwks.json", json!(null)),
            )
            .await,
        );

        let restarted = Arc::new(
            Store::new_with_tier(dir.clone(), TierConfig::default())
                .expect("persisted subscription state must reload"),
        );
        restarted
            .subscriptions
            .resume(restarted.clone())
            .await
            .unwrap();
        let restarted_jwks = response_json(
            handle(
                restarted.clone(),
                json_request(Method::Get, "/root/__ds/jwks.json", json!(null)),
            )
            .await,
        );
        assert_eq!(restarted_jwks, original_jwks, "signing key must be stable");

        let mut ack = json_request(
            Method::Post,
            "/root/__ds/subscriptions/sub-1/ack",
            json!({
                "wake_id": claim["wake_id"],
                "generation": claim["generation"],
                "acks": [{
                    "stream": "events/a",
                    "offset": claim["streams"].as_array().unwrap().iter()
                        .find(|stream| stream["path"] == "events/a").unwrap()["tail_offset"]
                }],
                "done": true
            }),
        );
        ack.headers.push((
            "authorization".into(),
            format!("Bearer {}", claim["token"].as_str().unwrap()),
        ));
        assert_eq!(
            handle(restarted.clone(), ack).await.status,
            200,
            "the persisted callback-token key and active lease must validate after restart"
        );
        {
            let state = restarted.subscriptions.state.lock().await;
            let subscription = state
                .subscriptions
                .get(&subscription_key("/root", "sub-1"))
                .unwrap();
            assert!(subscription.wake_id.is_none());
            assert!(!has_pending_work(subscription, &restarted));
        }
        assert!(dir.join("subscriptions/state.json").is_file());
        assert!(dir.join("subscriptions/secrets.json").is_file());

        drop(restarted);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restart_reconciles_a_glob_append_missing_from_the_last_snapshot() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("glob-crash-window");
        create_json_stream(&store, "/root/wake/pool").await;
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
        let before_append = {
            let state = store.subscriptions.state.lock().await;
            PersistedState {
                version: STATE_VERSION,
                subscriptions: state.subscriptions.values().cloned().collect(),
            }
        };
        create_json_stream(&store, "/root/events/a").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        // Model a crash after the source append became durable but before its
        // derived subscription snapshot replacement reached disk.
        atomic_write_json(&dir.join("subscriptions/state.json"), &before_append).unwrap();
        store.subscriptions.state.lock().await.subscriptions.clear();

        let restarted = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        restarted
            .subscriptions
            .resume(restarted.clone())
            .await
            .unwrap();
        let state = restarted.subscriptions.state.lock().await;
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap();
        assert_eq!(
            subscription.streams.get("events/a").unwrap().acked_offset,
            BEFORE_FIRST_OFFSET
        );
        assert!(subscription.wake_id.is_some());
        drop(state);

        drop(restarted);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn persisted_subscriptions_refuse_startup_without_their_secrets() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("missing-secrets");
        create_json_stream(&store, "/root/wake/pool").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(
                    Method::Put,
                    "/root/__ds/subscriptions/sub-1",
                    json!({
                        "type": "pull-wake",
                        "streams": ["events/a"],
                        "wake_stream": "wake/pool"
                    }),
                ),
            )
            .await
            .status,
            201
        );
        std::fs::remove_file(dir.join("subscriptions/secrets.json")).unwrap();
        let error = match Store::new_with_tier(dir.clone(), TierConfig::default()) {
            Ok(_) => panic!("startup must not mint replacement subscription secrets"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("refusing to replace"));

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn persisted_retry_deadline_resumes_after_restart() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("durable-retry");
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
        {
            let state = store.subscriptions.state.lock().await;
            let subscription = state
                .subscriptions
                .get(&subscription_key("/root", "sub-1"))
                .unwrap();
            assert_eq!(subscription.status, SubscriptionStatus::Failed);
            assert!(subscription.next_attempt_at_ms.is_some());
        }
        create_json_stream(&store, "/root/wake/pool").await;
        // The source append admitted a detached coalescing snapshot writer.
        // A real restart cannot overlap that old process, so wait for the test
        // manager's writer to exit before opening a second manager on the same
        // directory (and therefore the same atomic-write temp namespace).
        store.subscriptions.drain_state_persistence().await;
        // Prevent the old manager's already-spawned retry from competing with
        // the fresh manager. This intentionally does not touch the durable
        // snapshot that the restarted manager loads.
        store.subscriptions.state.lock().await.subscriptions.clear();

        let restarted = Arc::new(Store::new_with_tier(dir.clone(), TierConfig::default()).unwrap());
        restarted
            .subscriptions
            .resume(restarted.clone())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if restarted.get("/root/wake/pool").unwrap().tail().bytes > 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the persisted retry must run without another source append"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        drop(restarted);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn stale_pull_delivery_retry_cannot_erase_a_new_worker_lease() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("retry-claim-race");
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
        let claim = handle(
            store.clone(),
            json_request(
                Method::Post,
                "/root/__ds/subscriptions/sub-1/claim",
                json!({"worker": "worker-a"}),
            ),
        )
        .await;
        assert_eq!(claim.status, 200);
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let state = store.subscriptions.state.lock().await;
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap();
        assert_eq!(subscription.holder.as_deref(), Some("worker-a"));
        assert!(subscription.lease_expires_at_ms.is_some());
        assert!(!subscription.wake_delivery_pending);
        drop(state);

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failed_webhook_delivery_is_fenced_by_the_issued_wake_lease() {
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
                    stream_id: live_stream_metadata(&store, "/root", "events/a").map(|(id, _)| id),
                },
            )]),
            generation: 0,
            wake_id: None,
            wake_snapshot: BTreeMap::new(),
            token: None,
            holder: None,
            lease_nonce: 0,
            retry_count: 0,
            next_attempt_at_ms: None,
            lease_expires_at_ms: None,
            wake_trigger: None,
            wake_delivery_pending: false,
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
        assert!(
            subscription.generation > 1,
            "the webhook lease must fence a failed delivery after its TTL"
        );
        assert!(subscription.lease_expires_at_ms.is_some());
        assert!(subscription.holder.is_none());
        drop(state);
        store.subscriptions.state.lock().await.subscriptions.clear();
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pull_done_only_acknowledges_explicitly_listed_streams() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("partial-done");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        create_json_stream(&store, "/root/events/b").await;
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
        for path in ["/root/events/a", "/root/events/b"] {
            assert_eq!(
                handle(
                    store.clone(),
                    json_request(Method::Post, path, json!({"value": path})),
                )
                .await
                .status,
                204
            );
        }
        let claim = response_json(
            handle(
                store.clone(),
                json_request(
                    Method::Post,
                    "/root/__ds/subscriptions/sub-1/claim",
                    json!({"worker": "worker-1"}),
                ),
            )
            .await,
        );
        let a_tail = claim["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stream| stream["path"] == "events/a")
            .unwrap()["tail_offset"]
            .clone();
        let mut ack = json_request(
            Method::Post,
            "/root/__ds/subscriptions/sub-1/ack",
            json!({
                "wake_id": claim["wake_id"],
                "generation": claim["generation"],
                "acks": [{"stream": "events/a", "offset": a_tail}],
                "done": true
            }),
        );
        ack.headers.push((
            "authorization".into(),
            format!("Bearer {}", claim["token"].as_str().unwrap()),
        ));
        let response = response_json(handle(store.clone(), ack).await);
        assert_eq!(response["next_wake"], true);
        let state = store.subscriptions.state.lock().await;
        let subscription = state
            .subscriptions
            .get(&subscription_key("/root", "sub-1"))
            .unwrap();
        assert_eq!(subscription.streams["events/a"].acked_offset, a_tail);
        assert_eq!(subscription.streams["events/b"].acked_offset, ZERO_OFFSET);
        assert!(has_pending_work(subscription, &store));
        assert!(subscription.wake_id.is_some());
        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn duplicate_acks_in_one_request_cannot_regress_a_cursor() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("duplicate-acks");
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
                        "streams": ["events/a"],
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
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let claim = response_json(
            handle(
                store.clone(),
                json_request(
                    Method::Post,
                    "/root/__ds/subscriptions/sub-1/claim",
                    json!({"worker": "worker-1"}),
                ),
            )
            .await,
        );
        let tail = claim["streams"][0]["tail_offset"].clone();
        let mut ack = json_request(
            Method::Post,
            "/root/__ds/subscriptions/sub-1/ack",
            json!({
                "wake_id": claim["wake_id"],
                "generation": claim["generation"],
                "acks": [
                    {"stream": "events/a", "offset": tail},
                    {"stream": "events/a", "offset": ZERO_OFFSET}
                ],
                "done": false
            }),
        );
        ack.headers.push((
            "authorization".into(),
            format!("Bearer {}", claim["token"].as_str().unwrap()),
        ));
        assert_eq!(handle(store.clone(), ack).await.status, 200);
        let state = store.subscriptions.state.lock().await;
        assert_eq!(
            state.subscriptions[&subscription_key("/root", "sub-1")].streams["events/a"]
                .acked_offset,
            tail
        );
        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn claim_reclaims_a_persisted_lease_that_is_already_expired() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("expired-claim");
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
                        "streams": ["events/a"],
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
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let first = response_json(
            handle(
                store.clone(),
                json_request(
                    Method::Post,
                    "/root/__ds/subscriptions/sub-1/claim",
                    json!({"worker": "worker-1"}),
                ),
            )
            .await,
        );
        store
            .subscriptions
            .state
            .lock()
            .await
            .subscriptions
            .get_mut(&subscription_key("/root", "sub-1"))
            .unwrap()
            .lease_expires_at_ms = Some(0);
        let second = handle(
            store.clone(),
            json_request(
                Method::Post,
                "/root/__ds/subscriptions/sub-1/claim",
                json!({"worker": "worker-2"}),
            ),
        )
        .await;
        assert_eq!(second.status, 200);
        let second = response_json(second);
        assert!(second["generation"].as_u64() > first["generation"].as_u64());
        assert_ne!(second["token"], first["token"]);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restart_fences_a_replaced_stream_incarnation() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("restart-incarnation");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let current_id = live_stream_metadata(&store, "/root", "events/a").unwrap().0;
        let subscription = Subscription {
            id: "sub-1".into(),
            stream_root: "/root".into(),
            config: SubscriptionConfig {
                kind: SubscriptionKind::PullWake,
                pattern: None,
                streams: vec!["events/a".into()],
                webhook_url: None,
                wake_stream: Some("wake/pool".into()),
                lease_ttl_ms: 600_000,
                description: None,
            },
            callback_base_url: "http://localhost:4562".into(),
            created_at: "2026-08-28T00:00:00Z".into(),
            status: SubscriptionStatus::Active,
            streams: BTreeMap::from([(
                "events/a".into(),
                StreamLink {
                    explicit: true,
                    glob: false,
                    acked_offset: format_offset(u64::MAX),
                    stream_id: Some(current_id.wrapping_add(1)),
                },
            )]),
            generation: 7,
            wake_id: Some("old-wake".into()),
            wake_snapshot: BTreeMap::from([("events/a".into(), format_offset(u64::MAX))]),
            token: Some("old-token".into()),
            holder: Some("old-worker".into()),
            lease_nonce: 4,
            retry_count: 0,
            next_attempt_at_ms: None,
            lease_expires_at_ms: Some(unix_millis().saturating_add(600_000)),
            wake_trigger: Some("events/a".into()),
            wake_delivery_pending: false,
        };
        {
            let mut state = store.subscriptions.state.lock().await;
            register_wake_stream(&mut state, &subscription, &store);
            state
                .subscriptions
                .insert(subscription_key("/root", "sub-1"), subscription);
        }
        store
            .subscriptions
            .subscription_count
            .fetch_add(1, Ordering::Release);
        store.subscriptions.resume(store.clone()).await.unwrap();
        let state = store.subscriptions.state.lock().await;
        let subscription = &state.subscriptions[&subscription_key("/root", "sub-1")];
        assert_eq!(subscription.streams["events/a"].stream_id, Some(current_id));
        assert_eq!(
            subscription.streams["events/a"].acked_offset,
            BEFORE_FIRST_OFFSET
        );
        assert_eq!(subscription.generation, 8);
        assert_ne!(subscription.wake_id.as_deref(), Some("old-wake"));
        assert!(subscription.holder.is_none());
        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn explicit_link_fences_a_lazy_expiry_replacement_without_delete_notification() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("explicit-expiry-incarnation");
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
                        "streams": ["events/a"],
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
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
            .status,
            204
        );
        let claim = response_json(
            handle(
                store.clone(),
                json_request(
                    Method::Post,
                    "/root/__ds/subscriptions/sub-1/claim",
                    json!({"worker": "worker-1"}),
                ),
            )
            .await,
        );
        let old_tail = claim["streams"][0]["tail_offset"].clone();
        let old_id = live_stream_metadata(&store, "/root", "events/a").unwrap().0;
        let mut ack = json_request(
            Method::Post,
            "/root/__ds/subscriptions/sub-1/ack",
            json!({
                "wake_id": claim["wake_id"],
                "generation": claim["generation"],
                "acks": [{"stream": "events/a", "offset": old_tail}],
                "done": true
            }),
        );
        ack.headers.push((
            "authorization".into(),
            format!("Bearer {}", claim["token"].as_str().unwrap()),
        ));
        assert_eq!(handle(store.clone(), ack).await.status, 200);

        // Model Store::get's lazy TTL unlink directly: unlike the HTTP DELETE
        // path it intentionally does not call `on_stream_deleted`.
        let expired = store.get("/root/events/a").unwrap();
        store.delete_or_soft_delete_durable(&expired).unwrap();
        create_json_stream(&store, "/root/events/a").await;
        assert_eq!(
            handle(
                store.clone(),
                json_request(Method::Post, "/root/events/a", json!({"value": 2})),
            )
            .await
            .status,
            204
        );

        let new_id = live_stream_metadata(&store, "/root", "events/a").unwrap().0;
        assert_ne!(new_id, old_id);
        let state = store.subscriptions.state.lock().await;
        let subscription = &state.subscriptions[&subscription_key("/root", "sub-1")];
        assert_eq!(subscription.streams["events/a"].stream_id, Some(new_id));
        assert_eq!(
            subscription.streams["events/a"].acked_offset,
            BEFORE_FIRST_OFFSET
        );
        assert!(subscription.wake_id.is_some());
        assert!(has_pending_work(subscription, &store));
        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn append_waits_for_a_first_subscription_create_after_its_tail_sample() {
        let _guard = DurabilityGuard::memory();
        let (store, dir) = test_store("first-create-append-race");
        create_json_stream(&store, "/root/wake/pool").await;
        create_json_stream(&store, "/root/events/a").await;
        let stream_id = live_stream_metadata(&store, "/root", "events/a").unwrap().0;
        let subscription = Subscription {
            id: "sub-1".into(),
            stream_root: "/root".into(),
            config: SubscriptionConfig {
                kind: SubscriptionKind::PullWake,
                pattern: None,
                streams: vec!["events/a".into()],
                webhook_url: None,
                wake_stream: Some("wake/pool".into()),
                lease_ttl_ms: 30_000,
                description: None,
            },
            callback_base_url: String::new(),
            created_at: "2026-08-28T00:00:00Z".into(),
            status: SubscriptionStatus::Active,
            streams: BTreeMap::from([(
                "events/a".into(),
                StreamLink {
                    explicit: true,
                    glob: false,
                    acked_offset: ZERO_OFFSET.into(),
                    stream_id: Some(stream_id),
                },
            )]),
            generation: 0,
            wake_id: None,
            wake_snapshot: BTreeMap::new(),
            token: None,
            holder: None,
            lease_nonce: 0,
            retry_count: 0,
            next_attempt_at_ms: None,
            lease_expires_at_ms: None,
            wake_trigger: None,
            wake_delivery_pending: false,
        };

        // Hold the manager lock to pause a modeled first create after it has
        // sampled the source tail but before insertion. The append must see the
        // in-progress counter and wait instead of taking the zero-count return.
        let manager = store.subscriptions.clone();
        let mut state = manager.state.lock().await;
        // This reservation is the modeled create guard; after insertion it
        // becomes the committed subscription count without an atomic handoff.
        manager.subscription_count.fetch_add(1, Ordering::Release);
        let append_store = store.clone();
        let append = tokio::spawn(async move {
            handle(
                append_store,
                json_request(Method::Post, "/root/events/a", json!({"value": 1})),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while live_tail_offset(&store, "/root", "events/a").as_deref() == Some(ZERO_OFFSET) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("append should publish its durable tail before waiting on subscription state");
        register_wake_stream(&mut state, &subscription, &store);
        state
            .subscriptions
            .insert(subscription_key("/root", "sub-1"), subscription);
        drop(state);

        assert_eq!(append.await.unwrap().status, 204);
        let state = manager.state.lock().await;
        let subscription = &state.subscriptions[&subscription_key("/root", "sub-1")];
        assert!(subscription.wake_id.is_some());
        assert!(has_pending_work(subscription, &store));
        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
