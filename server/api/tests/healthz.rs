//! Role: Integration test for `GET /healthz`. Uses tower::ServiceExt::oneshot
//!       so the test runs without binding a socket.
//! Target platforms: server (any tokio-supported OS).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn healthz_returns_ok() {
    let app = api::build_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("request builder accepts a valid uri"),
        )
        .await
        .expect("oneshot does not fail for a valid router");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collecting body bytes")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("body is valid JSON");
    assert_eq!(value["status"], "ok");
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let app = api::build_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/this/route/does/not/exist")
                .body(Body::empty())
                .expect("request builder accepts a valid uri"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
