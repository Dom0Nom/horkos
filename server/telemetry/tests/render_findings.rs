//! tests/render_findings.rs
//! Role: Integration test for the render/overlay-hook ingest plane
//!       (POST /api/render-findings): a valid batch -> 202; a wrong envelope
//!       schema_version -> 400 via TelemetryError::RenderSchema; a finding-level
//!       schema mismatch -> 400. Mirrors tests/ingest.rs.
//! Target platforms: server.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use telemetry::render_hook::{RenderFinding, RenderFindingBatch, RENDER_SCHEMA_VERSION};
use tower::ServiceExt;

fn one_finding() -> RenderFinding {
    RenderFinding {
        schema_version: RENDER_SCHEMA_VERSION,
        signal: 49,
        verdict: 4,
        style_bits: 0x25,
        owning_pid: 4242,
        slot_index: 0,
        target_addr: 0,
        region_hash: 0,
        cadence_drift_ns: 0,
        module_path: None,
        signer_subject: None,
        window_class: Some("OverlayClass".into()),
    }
}

#[tokio::test]
async fn valid_batch_returns_202() {
    let app = telemetry::router();

    let batch = RenderFindingBatch {
        schema_version: RENDER_SCHEMA_VERSION,
        player_id: 7,
        findings: vec![one_finding()],
    };
    let body = serde_json::to_vec(&batch).expect("serialise render batch");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/render-findings")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn empty_findings_batch_returns_202() {
    let app = telemetry::router();

    let batch = RenderFindingBatch {
        schema_version: RENDER_SCHEMA_VERSION,
        player_id: 7,
        findings: vec![],
    };
    let body = serde_json::to_vec(&batch).expect("serialise");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/render-findings")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
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
        "findings": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/render-findings")
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
    assert_eq!(value["status"], "render_schema_mismatch");
}

#[tokio::test]
async fn finding_level_schema_mismatch_returns_400() {
    let app = telemetry::router();

    // Envelope is current, but a single finding carries a future version.
    let body = serde_json::json!({
        "schema_version": RENDER_SCHEMA_VERSION,
        "player_id": 1,
        "findings": [{
            "schema_version": 999,
            "signal": 46,
            "verdict": 0,
            "style_bits": 0,
            "owning_pid": 0,
            "slot_index": 0,
            "target_addr": 0,
            "region_hash": 0,
            "cadence_drift_ns": 0
        }]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/render-findings")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let app = telemetry::router();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/render-findings")
                .header("content-type", "application/json")
                .body(Body::from("{not valid json"))
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
