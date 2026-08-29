//! Service-JWT verification for pull-wake claims.
//!
//! The Durable Streams protocol requires a service JWT but deliberately does
//! not prescribe an identity provider. This module provides a small operator
//! contract: a mounted JWKS file, an exact issuer, an exact audience, and an
//! optional required OAuth-style scope/subject. A validated JWKS is cached for
//! at most one second, so atomic replacement rotates trust without making each
//! attacker-controlled claim perform filesystem I/O.

#![cfg_attr(test, allow(dead_code))]

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

const JWKS_FILE_ENV: &str = "DS_SUBSCRIPTION_SERVICE_JWT_JWKS_FILE";
const ISSUER_ENV: &str = "DS_SUBSCRIPTION_SERVICE_JWT_ISSUER";
const AUDIENCE_ENV: &str = "DS_SUBSCRIPTION_SERVICE_JWT_AUDIENCE";
const SCOPE_ENV: &str = "DS_SUBSCRIPTION_SERVICE_JWT_REQUIRED_SCOPE";
const SUBJECT_ENV: &str = "DS_SUBSCRIPTION_SERVICE_JWT_REQUIRED_SUBJECT";
const INSECURE_ENV: &str = "DS_SUBSCRIPTION_INSECURE_ALLOW_UNAUTHENTICATED_CLAIMS";
const JWKS_CACHE_TTL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct ServiceJwtVerifier {
    mode: Mode,
}

#[derive(Clone)]
enum Mode {
    Unconfigured,
    InsecureDevelopment,
    Jwks(Arc<VerifierConfig>),
}

#[derive(Clone)]
struct VerifierConfig {
    jwks_file: PathBuf,
    issuer: String,
    audience: String,
    required_scope: Option<String>,
    required_subject: Option<String>,
    cache: Arc<Mutex<CachedJwks>>,
}

struct CachedJwks {
    loaded_at: Instant,
    keys: JwkSet,
    reload_failed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceJwtError {
    Unavailable,
    Missing,
    Invalid,
    Forbidden,
}

impl ServiceJwtVerifier {
    pub(crate) fn from_env() -> io::Result<Self> {
        if env_flag(INSECURE_ENV)? {
            tracing::warn!(
                "pull-wake service-JWT verification is disabled by an explicit insecure flag"
            );
            return Ok(Self {
                mode: Mode::InsecureDevelopment,
            });
        }

        let jwks_file = nonempty_env(JWKS_FILE_ENV);
        let issuer = nonempty_env(ISSUER_ENV);
        let audience = nonempty_env(AUDIENCE_ENV);
        if jwks_file.is_none() && issuer.is_none() && audience.is_none() {
            return Ok(Self {
                mode: Mode::Unconfigured,
            });
        }
        let (Some(jwks_file), Some(issuer), Some(audience)) = (jwks_file, issuer, audience) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{JWKS_FILE_ENV}, {ISSUER_ENV}, and {AUDIENCE_ENV} must be configured together"
                ),
            ));
        };
        let keys = load_jwks(&PathBuf::from(&jwks_file))?;
        let config = VerifierConfig {
            jwks_file: PathBuf::from(jwks_file),
            issuer,
            audience,
            required_scope: nonempty_env(SCOPE_ENV),
            required_subject: nonempty_env(SUBJECT_ENV),
            cache: Arc::new(Mutex::new(CachedJwks {
                loaded_at: Instant::now(),
                keys,
                reload_failed: false,
            })),
        };
        Ok(Self {
            mode: Mode::Jwks(Arc::new(config)),
        })
    }

    pub(crate) async fn verify(&self, bearer_token: Option<String>) -> Result<(), ServiceJwtError> {
        let config = match &self.mode {
            Mode::Unconfigured => return Err(ServiceJwtError::Unavailable),
            Mode::InsecureDevelopment => return Ok(()),
            Mode::Jwks(config) => config.clone(),
        };
        let token = bearer_token.ok_or(ServiceJwtError::Missing)?;
        tokio::task::spawn_blocking(move || verify_with_jwks(&config, &token))
            .await
            .map_err(|_| ServiceJwtError::Invalid)?
    }

    #[cfg(test)]
    pub(crate) fn insecure_for_tests() -> Self {
        Self {
            mode: Mode::InsecureDevelopment,
        }
    }
}

fn verify_with_jwks(config: &VerifierConfig, token: &str) -> Result<(), ServiceJwtError> {
    let header = decode_header(token).map_err(|_| ServiceJwtError::Invalid)?;
    if !allowed_algorithm(header.alg) {
        return Err(ServiceJwtError::Invalid);
    }
    let kid = header.kid.as_deref().ok_or(ServiceJwtError::Invalid)?;
    let mut cache = config
        .cache
        .lock()
        .map_err(|_| ServiceJwtError::Unavailable)?;
    if cache.loaded_at.elapsed() >= JWKS_CACHE_TTL {
        cache.loaded_at = Instant::now();
        match load_jwks(&config.jwks_file) {
            Ok(keys) => {
                cache.keys = keys;
                cache.reload_failed = false;
            }
            Err(_) => {
                cache.reload_failed = true;
                return Err(ServiceJwtError::Unavailable);
            }
        }
    }
    if cache.reload_failed {
        return Err(ServiceJwtError::Unavailable);
    }
    let jwk = cache
        .keys
        .find(kid)
        .cloned()
        .ok_or(ServiceJwtError::Invalid)?;
    drop(cache);
    if !jwk_authorizes_algorithm(&jwk, header.alg) {
        return Err(ServiceJwtError::Invalid);
    }
    let key = DecodingKey::from_jwk(&jwk).map_err(|_| ServiceJwtError::Invalid)?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    if let Some(subject) = &config.required_subject {
        validation.sub = Some(subject.clone());
        validation.required_spec_claims.insert("sub".to_string());
    }
    validation.validate_exp = true;
    validation.validate_nbf = true;
    let claims = decode::<Value>(token, &key, &validation)
        .map_err(|_| ServiceJwtError::Invalid)?
        .claims;
    if config
        .required_scope
        .as_deref()
        .is_some_and(|scope| !has_scope(&claims, scope))
    {
        return Err(ServiceJwtError::Forbidden);
    }
    Ok(())
}

fn jwk_authorizes_algorithm(jwk: &Jwk, algorithm: Algorithm) -> bool {
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|usage| usage != &PublicKeyUse::Signature)
        || jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| {
                !operations
                    .iter()
                    .any(|operation| operation == &KeyOperations::Verify)
            })
    {
        return false;
    }
    if jwk
        .common
        .key_algorithm
        .is_some_and(|key_algorithm| !key_algorithm_matches(key_algorithm, algorithm))
    {
        return false;
    }
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => matches!(
            algorithm,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
        ),
        AlgorithmParameters::EllipticCurve(parameters) => matches!(
            (&parameters.curve, algorithm),
            (EllipticCurve::P256, Algorithm::ES256) | (EllipticCurve::P384, Algorithm::ES384)
        ),
        AlgorithmParameters::OctetKeyPair(parameters) => {
            parameters.curve == EllipticCurve::Ed25519 && algorithm == Algorithm::EdDSA
        }
        AlgorithmParameters::OctetKey(_) => false,
    }
}

fn key_algorithm_matches(key_algorithm: KeyAlgorithm, algorithm: Algorithm) -> bool {
    matches!(
        (key_algorithm, algorithm),
        (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::PS384, Algorithm::PS384)
            | (KeyAlgorithm::PS512, Algorithm::PS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
            | (KeyAlgorithm::EdDSA, Algorithm::EdDSA)
    )
}

fn allowed_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

fn has_scope(claims: &Value, required: &str) -> bool {
    match claims.get("scope") {
        Some(Value::String(scopes)) => scopes
            .split_ascii_whitespace()
            .any(|scope| scope == required),
        Some(Value::Array(scopes)) => scopes.iter().any(|scope| scope.as_str() == Some(required)),
        _ => false,
    }
}

fn load_jwks(path: &PathBuf) -> io::Result<JwkSet> {
    let bytes = std::fs::read(path)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("service-JWT JWKS {} exceeds 1 MiB", path.display()),
        ));
    }
    let jwks: JwkSet = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid service-JWT JWKS {}: {error}", path.display()),
        )
    })?;
    let mut kids = std::collections::HashSet::new();
    if jwks.keys.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("service-JWT JWKS {} contains no keys", path.display()),
        ));
    }
    for jwk in &jwks.keys {
        let Some(kid) = jwk.common.key_id.as_deref() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("service-JWT JWKS {} has a key without kid", path.display()),
            ));
        };
        if kid.is_empty() || !kids.insert(kid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "service-JWT JWKS {} has an empty or duplicate kid",
                    path.display()
                ),
            ));
        }
    }
    Ok(jwks)
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_flag(name: &str) -> io::Result<bool> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        Ok(value) if value == "0" || value.is_empty() => Ok(false),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be 0 or 1"),
        )),
        Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn scope_accepts_oauth_string_and_array_forms() {
        assert!(has_scope(
            &serde_json::json!({"scope": "read claim write"}),
            "claim"
        ));
        assert!(has_scope(
            &serde_json::json!({"scope": ["read", "claim"]}),
            "claim"
        ));
        assert!(!has_scope(
            &serde_json::json!({"scope": "claim-other"}),
            "claim"
        ));
    }

    #[test]
    fn symmetric_algorithms_are_never_accepted_for_jwks_claim_auth() {
        assert!(!allowed_algorithm(Algorithm::HS256));
        assert!(allowed_algorithm(Algorithm::EdDSA));
        assert!(allowed_algorithm(Algorithm::RS256));
    }

    #[test]
    fn jwk_metadata_must_authorize_the_requested_signature_algorithm() {
        let signing: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": "AA", "kid": "one",
            "use": "sig", "key_ops": ["verify"], "alg": "EdDSA"
        }))
        .unwrap();
        assert!(jwk_authorizes_algorithm(&signing, Algorithm::EdDSA));

        let encryption: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": "AA", "kid": "two",
            "use": "enc", "alg": "EdDSA"
        }))
        .unwrap();
        assert!(!jwk_authorizes_algorithm(&encryption, Algorithm::EdDSA));

        let wrong_operation: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": "AA", "kid": "three",
            "key_ops": ["sign"], "alg": "EdDSA"
        }))
        .unwrap();
        assert!(!jwk_authorizes_algorithm(
            &wrong_operation,
            Algorithm::EdDSA
        ));
    }

    #[test]
    fn duplicate_jwks_kids_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwks.json");
        std::fs::write(
            &path,
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AA","kid":"same"},{"kty":"OKP","crv":"Ed25519","x":"AQ","kid":"same"}]}"#,
        )
        .unwrap();
        assert!(load_jwks(&path).is_err());
    }

    #[tokio::test]
    async fn unconfigured_verifier_fails_closed() {
        let verifier = ServiceJwtVerifier {
            mode: Mode::Unconfigured,
        };
        assert_eq!(
            verifier.verify(Some("unused".to_string())).await,
            Err(ServiceJwtError::Unavailable)
        );
    }

    #[test]
    fn verifies_signature_issuer_audience_expiry_and_scope() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let kid = "service-key-1";
        let dir = tempfile::tempdir().unwrap();
        let jwks_file = dir.path().join("jwks.json");
        std::fs::write(
            &jwks_file,
            serde_json::to_vec(&serde_json::json!({
                "keys": [{
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": kid,
                    "use": "sig",
                    "alg": "EdDSA",
                    "x": base64_url(pair.public_key().as_ref())
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let cached_keys = load_jwks(&jwks_file).unwrap();
        let config = VerifierConfig {
            jwks_file,
            issuer: "https://identity.example".into(),
            audience: "durable-streams".into(),
            required_scope: Some("streams:claim".into()),
            required_subject: None,
            cache: Arc::new(Mutex::new(CachedJwks {
                loaded_at: Instant::now(),
                keys: cached_keys,
                reload_failed: false,
            })),
        };
        let header = base64_url(
            serde_json::to_string(&serde_json::json!({"alg": "EdDSA", "kid": kid}))
                .unwrap()
                .as_bytes(),
        );
        let payload = base64_url(
            serde_json::to_string(&serde_json::json!({
                "iss": "https://identity.example",
                "aud": "durable-streams",
                "exp": unix_seconds() + 60,
                "scope": "streams:read streams:claim"
            }))
            .unwrap()
            .as_bytes(),
        );
        let unsigned = format!("{header}.{payload}");
        let token = format!(
            "{unsigned}.{}",
            base64_url(pair.sign(unsigned.as_bytes()).as_ref())
        );
        assert_eq!(verify_with_jwks(&config, &token), Ok(()));

        let wrong_audience = VerifierConfig {
            audience: "another-service".into(),
            ..config.clone()
        };
        assert_eq!(
            verify_with_jwks(&wrong_audience, &token),
            Err(ServiceJwtError::Invalid)
        );
        let wrong_scope = VerifierConfig {
            required_scope: Some("streams:admin".into()),
            ..config
        };
        assert_eq!(
            verify_with_jwks(&wrong_scope, &token),
            Err(ServiceJwtError::Forbidden)
        );
    }

    fn unix_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn base64_url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let bits = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            output.push(ALPHABET[((bits >> 18) & 63) as usize] as char);
            output.push(ALPHABET[((bits >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[((bits >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(bits & 63) as usize] as char);
            }
        }
        output
    }
}
