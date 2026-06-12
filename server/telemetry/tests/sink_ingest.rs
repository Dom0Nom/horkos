//! Role: HTTP integration for `router_with_sink` — validated ticks are
//! stamped server-side and forwarded into the pipeline channel; the
//! server-authored `server_received_ts` field can never be client-supplied
//! (a forgeable receive clock would poison the arrival-cadence detector);
//! backpressure surfaces as 503, a dead pipeline as 500.
//!
//! Target platforms: server (host-runnable).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use telemetry::schema::TickPayload;
use telemetry::sink::TickSink;
use tokio::sync::mpsc;
use tower::ServiceExt;

fn app_with_channel(capacity: usize) -> (axum::Router, mpsc::Receiver<TickPayload>) {
    let (tx, rx) = mpsc::channel(capacity);
    let app = telemetry::router_with_sink(Arc::new(TickSink::new(vec![tx])));
    (app, rx)
}

fn post(json: &str) -> Request<Body> {
    Request::post("/api/telemetry")
        .header("content-type", "application/json")
        .body(Body::from(json.to_string()))
        .expect("request")
}

#[tokio::test]
async fn valid_tick_is_stamped_and_forwarded() {
    let (app, mut rx) = app_with_channel(8);
    let res = app
        .oneshot(post(
            r#"{"schema_version":6,"player_id":9,"tick":3,"aim_delta_x":0,"aim_delta_y":0,"input_state":0}"#,
        ))
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let fwd = rx.try_recv().expect("forwarded into the pipeline channel");
    assert_eq!(fwd.player_id, 9);
    assert_eq!(fwd.tick, 3);
    assert!(
        fwd.server_received_ts > 0,
        "server stamped the receive clock"
    );
}

#[tokio::test]
async fn forged_receive_timestamp_is_overwritten() {
    // ATTACK: the client ships its own `server_received_ts` (serde would
    // happily deserialize it). The stamp must be unconditional.
    let (app, mut rx) = app_with_channel(8);
    let res = app
        .oneshot(post(
            r#"{"schema_version":6,"player_id":9,"tick":3,"aim_delta_x":0,"aim_delta_y":0,"input_state":0,"server_received_ts":1}"#,
        ))
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let fwd = rx.try_recv().expect("forwarded");
    assert_ne!(fwd.server_received_ts, 1, "forged stamp must not survive");
    assert!(fwd.server_received_ts > 1_000_000_000_000_000_000); // sanity: ~2001+
}

#[tokio::test]
async fn invalid_payload_is_rejected_not_forwarded() {
    let (app, mut rx) = app_with_channel(8);
    let res = app
        .oneshot(post(
            r#"{"schema_version":99,"player_id":9,"tick":3,"aim_delta_x":0,"aim_delta_y":0,"input_state":0}"#,
        ))
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        rx.try_recv().is_err(),
        "rejected tick never reaches the pipeline"
    );
}

#[tokio::test]
async fn full_channel_returns_503() {
    let (app, _rx) = app_with_channel(1);
    let body = r#"{"schema_version":6,"player_id":9,"tick":1,"aim_delta_x":0,"aim_delta_y":0,"input_state":0}"#;
    let res = app.clone().oneshot(post(body)).await.expect("response");
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let res = app.oneshot(post(body)).await.expect("response");
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn dead_pipeline_returns_500() {
    let (app, rx) = app_with_channel(1);
    drop(rx);
    let res = app
        .oneshot(post(
            r#"{"schema_version":6,"player_id":9,"tick":1,"aim_delta_x":0,"aim_delta_y":0,"input_state":0}"#,
        ))
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
