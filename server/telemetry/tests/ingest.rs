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
        ..Default::default()
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

#[tokio::test]
async fn v1_payload_still_accepted_during_migration() {
    // A v1 client omits the entire v2 aim-feature block. It must still ingest
    // (202) during the migration window; the missing fields default to zero.
    let app = telemetry::router();

    let body = serde_json::json!({
        "schema_version": 1,
        "player_id": 7,
        "tick": 3,
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

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[test]
fn schema_version_is_six() {
    // v2 added the aim-feature block; v3 added the three game-state binding
    // fields (`client_mono_ns`, `client_refresh_hz`, `fired`); v4 added the
    // network-anomaly fields; v5 added the optional anti-analysis sub-payload;
    // v6 adds the optional hypervisor-state sub-payload.
    assert_eq!(SCHEMA_VERSION, 6);
}

#[test]
fn v1_json_deserializes_with_aim_defaults() {
    // A v1 payload (no aim-feature fields) round-trips into a v2 TickPayload
    // with the aim block defaulted to zero/false — never a fabricated signal.
    let v1 = serde_json::json!({
        "schema_version": 1,
        "player_id": 9,
        "tick": 100,
        "aim_delta_x": 1.5,
        "aim_delta_y": -2.0,
        "input_state": 5
    });
    let parsed: TickPayload = serde_json::from_value(v1).expect("v1 deserializes");
    assert_eq!(parsed.hid_report_count, 0);
    assert_eq!(parsed.injected_event_fraction_q8, 0);
    assert!(!parsed.virtual_device_present);
    assert!(parsed.candidate_target_offsets.is_empty());
    assert!(!parsed.impulse_is_direction_change);
}

#[test]
fn v2_payload_round_trips() {
    let mut payload = TickPayload {
        schema_version: SCHEMA_VERSION,
        player_id: 11,
        tick: 200,
        aim_delta_x: 0.1,
        aim_delta_y: 0.2,
        input_state: 3,
        hid_report_count: 8,
        hid_raw_dx: 40,
        hid_raw_dy: -12,
        hid_newest_ts_ns: 123_456_789,
        sens_scalar_q16: 0x0001_8000,
        applied_angle_dx: 0.01,
        applied_angle_dy: -0.02,
        hid_interval_framelock_count: 2,
        ang_vel: 3.0,
        injected_event_fraction_q8: 128,
        virtual_device_present: true,
        ..Default::default()
    };
    payload.candidate_target_offsets = vec![0.1, 0.5, 1.2];

    let bytes = serde_json::to_vec(&payload).expect("serialise v2 tick");
    let back: TickPayload = serde_json::from_slice(&bytes).expect("deserialise v2 tick");
    assert_eq!(payload, back);
}

#[tokio::test]
async fn ort_marker_route_unaffected() {
    // Sanity: the ort linkage marker is independent of the schema bump.
    assert_eq!(telemetry::ort_linked_marker(), "ort: linked");
}

#[test]
fn ort_marker_string_present() {
    assert_eq!(telemetry::ort_linked_marker(), "ort: linked");
}
