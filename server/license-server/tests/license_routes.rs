//! Role: Real licence lifecycle assertions — issue mints a verifiable token,
//!       verify enforces signature + hardware binding + revocation, revoke
//!       invalidates, and tampering/forgery is rejected fail-closed. A shared
//!       service instance is used so issue and verify see the same key/store.
//! Target platforms: server.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use license_server::{router_with_service, LicenseService};
use tower::ServiceExt;

async fn post_json(
    svc: &LicenseService,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let app = router_with_service(svc.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("oneshot");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, value)
}

async fn issue(svc: &LicenseService, hw: &str) -> serde_json::Value {
    let (status, body) = post_json(
        svc,
        "/api/license/issue",
        serde_json::json!({ "account_id": "acct-1", "product_id": "horkos", "hardware_id": hw }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "issue: {body}");
    body
}

#[tokio::test]
async fn issued_token_verifies_for_its_hardware() {
    let svc = LicenseService::new();
    let issued = issue(&svc, "HW-AAAA").await;
    let token = issued["license_token"].as_str().expect("token");

    let (status, body) = post_json(
        &svc,
        "/api/license/verify",
        serde_json::json!({ "license_token": token, "hardware_id": "HW-AAAA" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "valid");
    assert_eq!(body["account_id"], "acct-1");
}

#[tokio::test]
async fn token_bound_to_other_hardware_is_rejected() {
    let svc = LicenseService::new();
    let token = issue(&svc, "HW-AAAA").await["license_token"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = post_json(
        &svc,
        "/api/license/verify",
        serde_json::json!({ "license_token": token, "hardware_id": "HW-BBBB" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["reason"], "hardware_mismatch");
}

#[tokio::test]
async fn tampered_claims_fail_signature() {
    let svc = LicenseService::new();
    let token = issue(&svc, "HW-AAAA").await["license_token"]
        .as_str()
        .unwrap()
        .to_string();
    // Flip a byte in the claims half of `hex(claims).hex(sig)`.
    let (claims, sig) = token.split_once('.').unwrap();
    let mut c: Vec<char> = claims.chars().collect();
    c[10] = if c[10] == 'a' { 'b' } else { 'a' };
    let tampered = format!("{}.{}", c.into_iter().collect::<String>(), sig);
    let (status, body) = post_json(
        &svc,
        "/api/license/verify",
        serde_json::json!({ "license_token": tampered, "hardware_id": "HW-AAAA" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A flipped claims byte either breaks JSON or the signature — both invalid.
    assert_eq!(body["status"], "invalid");
}

#[tokio::test]
async fn revoked_license_no_longer_verifies() {
    let svc = LicenseService::new();
    let issued = issue(&svc, "HW-AAAA").await;
    let token = issued["license_token"].as_str().unwrap().to_string();
    let license_id = issued["license_id"].as_str().unwrap().to_string();

    // Valid before revoke.
    let (status, _) = post_json(
        &svc,
        "/api/license/verify",
        serde_json::json!({ "license_token": token, "hardware_id": "HW-AAAA" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_json(
        &svc,
        "/api/license/revoke",
        serde_json::json!({ "license_id": license_id, "reason": "test" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "revoked");

    let (status, body) = post_json(
        &svc,
        "/api/license/verify",
        serde_json::json!({ "license_token": token, "hardware_id": "HW-AAAA" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["reason"], "revoked");
}

#[tokio::test]
async fn revoking_unknown_license_is_404() {
    let svc = LicenseService::new();
    let (status, _) = post_json(
        &svc,
        "/api/license/revoke",
        serde_json::json!({ "license_id": "lic-99999999", "reason": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn garbage_token_is_rejected() {
    let svc = LicenseService::new();
    let (status, body) = post_json(
        &svc,
        "/api/license/verify",
        serde_json::json!({ "license_token": "not-a-token", "hardware_id": "HW" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["status"], "invalid_token");
}

#[tokio::test]
async fn issue_rejects_empty_fields() {
    let svc = LicenseService::new();
    let (status, body) = post_json(
        &svc,
        "/api/license/issue",
        serde_json::json!({ "account_id": "", "product_id": "p", "hardware_id": "h" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["status"], "invalid");
}
