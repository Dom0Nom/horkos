//! tests/ingest.rs
//! Role: Integration test: valid payload -> 202; invalid payload -> 400.
//!       Also asserts the ort linkage marker so the riskiest dependency
//!       on first install is exercised end-to-end.
//! Target platforms: server.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use telemetry::schema::{TickPayload, SCHEMA_VERSION};
use tower::ServiceExt;

#[tokio::test]
async fn valid_tick_returns_202() {
    let app = telemetry::router();

    let payload = TickPayload {
        schema_version: SCHEMA_VERSION,
        player_id: 1,
        tick: 42,
        aim_delta_x: 0.5,
        aim_delta_y: -0.25,
        input_state: 0b0000_0001,
        server_received_ts: 0,
    };
    let body = serde_json::to_vec(&payload).expect("serialise tick payload");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/telemetry")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn invalid_schema_version_returns_400() {
    let app = telemetry::router();

    let body = serde_json::json!({
        "schema_version": 999,
        "player_id": 1,
        "tick": 0,
        "aim_delta_x": 0.0,
        "aim_delta_y": 0.0,
        "input_state": 0
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/telemetry")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(value["status"], "invalid_payload");
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let app = telemetry::router();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/telemetry")
                .header("content-type", "application/json")
                .body(Body::from("{not valid json"))
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn ort_marker_string_present() {
    assert_eq!(telemetry::ort_linked_marker(), "ort: linked");
}
