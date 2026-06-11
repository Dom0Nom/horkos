//! src/lib.rs
//!
//! Role: Licence lifecycle routes — issue / revoke / verify. A licence is an
//! Ed25519-signed token binding an account + product to a specific hardware id;
//! verification checks the signature against the server's pinned key, the
//! hardware binding, expiry, and the in-memory revocation set. This is the
//! server-authoritative DRM trust root the client SDK's `drm_validate` calls
//! into.
//!
//! Scope (PoC): the signing key is a fixed-seed key and the issued/revoked
//! stores are in-memory — a real deployment pins a long-lived key (HSM/KMS) and
//! a durable store. The crypto, the binding, and the fail-closed verification
//! are real.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — `thiserror` via `LicenseError`; no `unwrap()` outside
//! tests; handlers are async with only short, never-awaited `std::sync::Mutex`
//! critical sections.

pub mod error;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, routing::post, Json, Router};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use error::LicenseError;
use serde::{Deserialize, Serialize};

/// Default licence validity: 365 days.
const DEFAULT_VALIDITY_NS: u64 = 365 * 24 * 60 * 60 * 1_000_000_000;

/// The signed licence claims. Field order fixes the canonical signing bytes
/// (re-serialized for both signing and verification — never the wire string).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct License {
    pub license_id: String,
    pub account_id: String,
    pub product_id: String,
    pub hardware_id: String,
    pub issued_at_ns: u64,
    pub expires_at_ns: u64,
}

impl License {
    fn signing_bytes(&self) -> Result<Vec<u8>, LicenseError> {
        serde_json::to_vec(self).map_err(|e| LicenseError::Internal(e.to_string()))
    }
}

/// The licence authority: holds the signing key and the issued/revoked stores.
/// Shared across the three routes via `State` so a token issued and verified on
/// the same instance round-trips.
#[derive(Clone)]
pub struct LicenseService {
    inner: Arc<Inner>,
}

struct Inner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    next_id: AtomicU64,
    issued: Mutex<HashMap<String, License>>,
    revoked: Mutex<HashSet<String>>,
}

impl LicenseService {
    /// New authority with a fixed-seed key (PoC). The fixed seed lets a
    /// restarted PoC server still verify tokens it issued in the same build; a
    /// real deployment injects a pinned key (HSM/KMS) instead.
    pub fn new() -> Self {
        let signing_key = SigningKey::from_bytes(&[0x5Au8; 32]);
        let verifying_key = signing_key.verifying_key();
        LicenseService {
            inner: Arc::new(Inner {
                signing_key,
                verifying_key,
                next_id: AtomicU64::new(1),
                issued: Mutex::new(HashMap::new()),
                revoked: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// The public key clients/SDK pin to verify licence tokens offline.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.verifying_key.to_bytes())
    }

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Mint a signed licence token. Token = `hex(claims_json).hex(sig)`.
    fn issue(&self, req: &IssueRequest) -> Result<IssueResponse, LicenseError> {
        let issued_at_ns = Self::now_ns();
        let n = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let license = License {
            license_id: format!("lic-{n:08}"),
            account_id: req.account_id.clone(),
            product_id: req.product_id.clone(),
            hardware_id: req.hardware_id.clone(),
            issued_at_ns,
            expires_at_ns: issued_at_ns.saturating_add(DEFAULT_VALIDITY_NS),
        };
        let claims = license.signing_bytes()?;
        let sig = self.inner.signing_key.sign(&claims);
        let token = format!("{}.{}", hex::encode(&claims), hex::encode(sig.to_bytes()));

        if let Ok(mut issued) = self.inner.issued.lock() {
            issued.insert(license.license_id.clone(), license.clone());
        }
        Ok(IssueResponse {
            status: "issued",
            license_id: license.license_id,
            license_token: token,
            expires_at_ns: license.expires_at_ns,
        })
    }

    fn revoke(&self, license_id: &str) -> Result<(), LicenseError> {
        let known = self
            .inner
            .issued
            .lock()
            .map(|m| m.contains_key(license_id))
            .unwrap_or(false);
        if !known {
            return Err(LicenseError::NotFound);
        }
        if let Ok(mut revoked) = self.inner.revoked.lock() {
            revoked.insert(license_id.to_string());
        }
        Ok(())
    }

    /// Verify a token: signature, hardware binding, expiry, revocation. Every
    /// failure is a typed error (fail-closed); a valid token returns the claims.
    fn verify(&self, token: &str, hardware_id: &str) -> Result<License, LicenseError> {
        let (claims_hex, sig_hex) = token
            .split_once('.')
            .ok_or(LicenseError::InvalidToken("missing separator"))?;
        let claims_bytes =
            hex::decode(claims_hex).map_err(|_| LicenseError::InvalidToken("claims not hex"))?;
        let sig_bytes: [u8; 64] = hex::decode(sig_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(LicenseError::InvalidToken("signature not 64-byte hex"))?;

        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        self.inner
            .verifying_key
            .verify_strict(&claims_bytes, &sig)
            .map_err(|_| LicenseError::SignatureInvalid)?;

        let license: License = serde_json::from_slice(&claims_bytes)
            .map_err(|_| LicenseError::InvalidToken("claims not a licence"))?;

        if license.hardware_id != hardware_id {
            return Err(LicenseError::HardwareMismatch);
        }
        if Self::now_ns() >= license.expires_at_ns {
            return Err(LicenseError::Expired);
        }
        let revoked = self
            .inner
            .revoked
            .lock()
            .map(|s| s.contains(&license.license_id))
            .unwrap_or(true); // poisoned lock => fail closed (treat as revoked)
        if revoked {
            return Err(LicenseError::Revoked);
        }
        Ok(license)
    }
}

impl Default for LicenseService {
    fn default() -> Self {
        Self::new()
    }
}

/// Router with a fresh in-memory authority.
pub fn router() -> Router {
    router_with_service(LicenseService::new())
}

/// Router over a provided authority (lets the host share one key/store).
pub fn router_with_service(service: LicenseService) -> Router {
    Router::new()
        .route("/api/license/issue", post(issue))
        .route("/api/license/revoke", post(revoke))
        .route("/api/license/verify", post(verify))
        .with_state(service)
}

// ---- Issue --------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    pub account_id: String,
    pub product_id: String,
    pub hardware_id: String,
}

#[derive(Debug, Serialize)]
pub struct IssueResponse {
    pub status: &'static str,
    pub license_id: String,
    pub license_token: String,
    pub expires_at_ns: u64,
}

#[tracing::instrument(skip_all, fields(account = %req.account_id, product = %req.product_id))]
async fn issue(
    State(svc): State<LicenseService>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, LicenseError> {
    if req.account_id.is_empty() || req.product_id.is_empty() || req.hardware_id.is_empty() {
        return Err(LicenseError::Invalid(
            "account_id, product_id, hardware_id required".into(),
        ));
    }
    Ok(Json(svc.issue(&req)?))
}

// ---- Revoke -------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub license_id: String,
    pub reason: String,
}

#[tracing::instrument(skip_all, fields(license = %req.license_id))]
async fn revoke(
    State(svc): State<LicenseService>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<serde_json::Value>, LicenseError> {
    if req.license_id.is_empty() {
        return Err(LicenseError::Invalid("license_id required".into()));
    }
    svc.revoke(&req.license_id)?;
    let _ = req.reason; // recorded by the audit layer in a real deployment
    Ok(Json(
        serde_json::json!({ "status": "revoked", "license_id": req.license_id }),
    ))
}

// ---- Verify -------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub license_token: String,
    pub hardware_id: String,
}

#[tracing::instrument(skip_all)]
async fn verify(
    State(svc): State<LicenseService>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, LicenseError> {
    if req.license_token.is_empty() || req.hardware_id.is_empty() {
        return Err(LicenseError::Invalid(
            "license_token and hardware_id required".into(),
        ));
    }
    let license = svc.verify(&req.license_token, &req.hardware_id)?;
    Ok(Json(serde_json::json!({
        "status": "valid",
        "license_id": license.license_id,
        "account_id": license.account_id,
        "product_id": license.product_id,
        "expires_at_ns": license.expires_at_ns,
    })))
}
