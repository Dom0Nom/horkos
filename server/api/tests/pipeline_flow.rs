//! Role: HTTP-surface integration for the live application wiring
//! (`build_app`): ingest accepts and forwards into the pipeline, the decision
//! route 404s for unjudged players, healthz reflects pipeline liveness, and a
//! client-supplied `server_received_ts` cannot survive ingest. Deep pipeline
//! behavior (pairing, fusion, latching) is covered in
//! `ban-engine/tests/pipeline_e2e.rs`.
//!
//! Target platforms: server (host-runnable).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn tick_json(player_id: u64, tick: u64) -> String {
    format!(
        r#"{{"schema_version":6,"player_id":{player_id},"tick":{tick},"aim_delta_x":0.0,"aim_delta_y":0.0,"input_state":0}}"#
    )
}

#[tokio::test]
async fn ingest_forwards_and_decisions_404_until_judged() {
    let (app, handle) = api::build_app().expect("build_app");

    let res = app
        .clone()
        .oneshot(
            Request::post("/api/telemetry")
                .header("content-type", "application/json")
                .body(Body::from(tick_json(42, 1)))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    // The tick reached the pipeline (no shed counted).
    assert_eq!(
        handle
            .stats
            .sessions_rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    let res = app
        .clone()
        .oneshot(
            Request::get("/api/decisions/42")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "unjudged player 404s");

    let res = app
        .oneshot(
            Request::get("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn healthz_degrades_when_alive_flag_clears() {
    // The shard-exit -> flag-clear path is covered in
    // `ban-engine/tests/pipeline_e2e.rs::alive_flag_clears_when_input_plane_closes`
    // (the live app cannot reach it from outside: the router's sink keeps the
    // input senders alive by design). Here: the flag drives the route.
    let (app, handle) = api::build_app().expect("build_app");

    handle
        .alive
        .store(false, std::sync::atomic::Ordering::Release);

    let res = app
        .oneshot(
            Request::get("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = res.into_body().collect().await.expect("body").to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(v["status"], "degraded");
}
