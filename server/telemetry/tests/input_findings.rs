//! tests/input_findings.rs
//! Role: Integration test for the input-provenance ingest plane
//!       (`POST /api/input-findings`, win-input-automation signals 55-63). A valid
//!       `InputFindingBatch` (findings + timing) -> 202; a wrong envelope
//!       `schema_version` -> 400 via `TelemetryError::InputSchema`. Mirrors the
//!       existing telemetry/render ingest integration tests.
//! Target platforms: server.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use telemetry::input_prov::{
    InputFinding, InputFindingBatch, InputTimingFeatures, INPUT_SCHEMA_VERSION,
    INPUT_TIMING_BUCKETS,
};
use tower::ServiceExt;

fn post(uri: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request")
}

#[tokio::test]
async fn valid_input_batch_returns_202() {
    let app = telemetry::router();

    let mut hist = [0u32; INPUT_TIMING_BUCKETS];
    hist[2] = 30;
    let batch = InputFindingBatch {
        schema_version: INPUT_SCHEMA_VERSION,
        player_id: 7,
        findings: vec![InputFinding {
            schema_version: INPUT_SCHEMA_VERSION,
            signal: 55,
            verdict: 5,
            flags: 0x0001,
            owning_pid: 0,
            event_count: 256,
            anomaly_count: 9,
            filter_count: 0,
            hdevice_token: 0xabc,
            llhook_latency_ns: 0,
            device_path: Some("\\\\?\\HID#VID_046D".into()),
            filter_service: None,
            signer_subject: None,
            vidpid: None,
            owning_image: None,
        }],
        timing: vec![InputTimingFeatures {
            schema_version: INPUT_SCHEMA_VERSION,
            signal: 58,
            hdevice_token: 0xabc,
            sample_count: 30,
            declared_hz: 0,
            observed_hz_x100: 100_000,
            transport_flags: 0x01,
            cov_x10000: 80,
            regularity_x10000: 9920,
            period_hist: hist,
        }],
    };
    let body = serde_json::to_vec(&batch).expect("serialise input batch");

    let response = app
        .oneshot(post("/api/input-findings", body))
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn wrong_envelope_schema_version_returns_400() {
    let app = telemetry::router();

    let body = serde_json::json!({
        "schema_version": 999,
        "player_id": 1,
        "findings": [],
        "timing": []
    });

    let response = app
        .oneshot(post("/api/input-findings", body.to_string().into_bytes()))
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
    assert_eq!(value["status"], "input_schema_mismatch");
}

#[tokio::test]
async fn misrouted_timing_signal_returns_400() {
    // A verdict-bearing signal (e.g. 55) must never arrive as a timing-feature block;
    // only 58/62 are features-only. The route rejects it.
    let app = telemetry::router();

    let body = serde_json::json!({
        "schema_version": INPUT_SCHEMA_VERSION,
        "player_id": 1,
        "findings": [],
        "timing": [{
            "schema_version": INPUT_SCHEMA_VERSION,
            "signal": 55,
            "hdevice_token": 0,
            "sample_count": 0,
            "declared_hz": 0,
            "observed_hz_x100": 0,
            "transport_flags": 0,
            "cov_x10000": 0,
            "regularity_x10000": 0,
            "period_hist": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }]
    });

    let response = app
        .oneshot(post("/api/input-findings", body.to_string().into_bytes()))
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
