//! tests/license_routes.rs
//! Role: Asserts each licence route returns 501 with the typed body in
//!       Phase 2. When real handlers land, these tests flip to real
//!       behaviour assertions.
//! Target platforms: server.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn post_json(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let app = license_server::router();
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

#[tokio::test]
async fn issue_returns_501_with_typed_body() {
    let (status, body) = post_json(
        "/api/license/issue",
        serde_json::json!({
            "account_id": "a",
            "product_id": "p",
            "hardware_id": "h"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["status"], "not_implemented");
}

#[tokio::test]
async fn revoke_returns_501_with_typed_body() {
    let (status, body) = post_json(
        "/api/license/revoke",
        serde_json::json!({
            "license_id": "l",
            "reason": "test"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["status"], "not_implemented");
}

#[tokio::test]
async fn verify_returns_501_with_typed_body() {
    let (status, body) = post_json(
        "/api/license/verify",
        serde_json::json!({
            "license_token": "tok",
            "hardware_id":   "hw"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["status"], "not_implemented");
}

#[tokio::test]
async fn issue_rejects_empty_fields() {
    let (status, body) = post_json(
        "/api/license/issue",
        serde_json::json!({
            "account_id": "",
            "product_id": "p",
            "hardware_id": "h"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["status"], "invalid");
}
