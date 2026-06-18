//! Role: verify optional anomaly-model configuration never removes API health.
//! Target platform: server test hosts. Interface: `api::build_app` and `/healthz`.

use std::ffi::OsString;

use axum::body::Body;
use http::{Request, StatusCode};
use tower::ServiceExt as _;

struct EnvRestore {
    value: Option<OsString>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.value {
            Some(value) => std::env::set_var("HORKOS_ANOMALY_MODEL", value),
            None => std::env::remove_var("HORKOS_ANOMALY_MODEL"),
        }
    }
}

async fn health_status() -> StatusCode {
    let (app, _pipeline) = api::build_app().unwrap();
    app.oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn health_stays_available_for_unset_invalid_and_valid_anomaly_models() {
    let _restore = EnvRestore {
        value: std::env::var_os("HORKOS_ANOMALY_MODEL"),
    };

    std::env::remove_var("HORKOS_ANOMALY_MODEL");
    assert_eq!(health_status().await, StatusCode::OK);

    std::env::set_var(
        "HORKOS_ANOMALY_MODEL",
        "/definitely/missing/horkos-anomaly.onnx",
    );
    assert_eq!(health_status().await, StatusCode::OK);

    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ban-engine/tests/fixtures/anomaly_score.onnx");
    std::env::set_var("HORKOS_ANOMALY_MODEL", fixture);
    assert_eq!(health_status().await, StatusCode::OK);
}
