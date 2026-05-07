//! src/lib.rs
//!
//! Role: Licence lifecycle routes. Phase 2 stubs return 501 with a typed
//! body so clients can compile against the URL surface; integration tests
//! assert the 501 contract.
//!
//! When real handlers land in a /tdd phase, integration tests flip to real
//! assertions on the issue / revoke / verify behaviour.
//!
//! Target platforms: server.

pub mod error;

use axum::{routing::post, Json, Router};
use error::LicenseError;
use serde::{Deserialize, Serialize};

pub fn router() -> Router {
    Router::new()
        .route("/api/license/issue", post(issue))
        .route("/api/license/revoke", post(revoke))
        .route("/api/license/verify", post(verify))
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
}

#[tracing::instrument(skip_all, fields(account = %req.account_id, product = %req.product_id))]
async fn issue(Json(req): Json<IssueRequest>) -> Result<Json<IssueResponse>, LicenseError> {
    if req.account_id.is_empty() || req.product_id.is_empty() || req.hardware_id.is_empty() {
        return Err(LicenseError::Invalid(
            "account_id, product_id, hardware_id required".into(),
        ));
    }
    Err(LicenseError::NotImplemented)
}

// ---- Revoke -------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub license_id: String,
    pub reason: String,
}

#[tracing::instrument(skip_all, fields(license = %req.license_id))]
async fn revoke(Json(req): Json<RevokeRequest>) -> Result<Json<serde_json::Value>, LicenseError> {
    if req.license_id.is_empty() {
        return Err(LicenseError::Invalid("license_id required".into()));
    }
    Err(LicenseError::NotImplemented)
}

// ---- Verify -------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub license_token: String,
    pub hardware_id: String,
}

#[tracing::instrument(skip_all)]
async fn verify(Json(req): Json<VerifyRequest>) -> Result<Json<serde_json::Value>, LicenseError> {
    if req.license_token.is_empty() || req.hardware_id.is_empty() {
        return Err(LicenseError::Invalid(
            "license_token and hardware_id required".into(),
        ));
    }
    Err(LicenseError::NotImplemented)
}
