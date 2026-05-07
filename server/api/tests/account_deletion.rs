//! tests/account_deletion.rs
//! Role: Asserts the GDPR-17 deletion route's 503 + Retry-After contract
//!       (Phase 2 stub). The contract flips to 202 only after the durable
//!       persistence layer lands under /tdd in a follow-up phase.
//! Target platforms: server (any tokio-supported OS).

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn delete_account_data_returns_503_with_retry_after() {
    let app = api::build_router();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/account/abc-123/data")
                .body(Body::empty())
                .expect("request builder"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let retry_after = response
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .expect("Retry-After header present");
    assert_eq!(retry_after.to_str().expect("ascii"), "86400");

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(value["status"], "unavailable");
    assert_eq!(value["reason"], "deletion service not yet provisioned");
}
