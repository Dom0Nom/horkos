//! tests/rules_route.rs
//! Role: Asserts `GET /api/rules/current` returns the placeholder metadata
//!       and that the bundle parser rejects unsigned bundles.
//! Target platforms: server.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ban_engine::bundle::{BundleLoader, RuleBundle};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn current_rules_returns_placeholder_metadata() {
    let app = ban_engine::router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rules/current")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(value["version"], 0);
    assert_eq!(value["signed_by"], "horkos-dev-placeholder");
}

#[test]
fn parse_rejects_unsigned_bundles() {
    let unsigned = serde_json::json!({
        "metadata": {
            "version": 1,
            "sha256": "deadbeef",
            "signed_by": "test",
            "expires_at": "2030-01-01T00:00:00Z"
        },
        "signature": "",
        "rules": []
    });
    let result = RuleBundle::parse(unsigned.to_string().as_bytes());
    assert!(matches!(
        result,
        Err(ban_engine::error::BanEngineError::BundleUnsigned)
    ));
}

#[test]
fn parse_rejects_malformed_json() {
    let result = RuleBundle::parse(b"not json");
    assert!(matches!(
        result,
        Err(ban_engine::error::BanEngineError::BundleSignatureInvalid)
    ));
}

#[cfg(not(feature = "unverified_bundles_dev_only"))]
#[test]
fn verify_returns_not_implemented_without_dev_feature() {
    let bundle = RuleBundle::parse(
        serde_json::json!({
            "metadata": {
                "version": 1,
                "sha256": "deadbeef",
                "signed_by": "test",
                "expires_at": "2030-01-01T00:00:00Z"
            },
            "signature": "0xfakebutpresent",
            "rules": []
        })
        .to_string()
        .as_bytes(),
    )
    .expect("parse signed bundle");

    let loader = BundleLoader::default();
    let result = loader.verify(&bundle);
    assert!(matches!(
        result,
        Err(ban_engine::error::BanEngineError::VerifierNotImplemented)
    ));
}

#[cfg(feature = "unverified_bundles_dev_only")]
#[test]
fn verify_accepts_signed_bundle_with_dev_feature() {
    let bundle = RuleBundle::parse(
        serde_json::json!({
            "metadata": {
                "version": 1,
                "sha256": "deadbeef",
                "signed_by": "test",
                "expires_at": "2030-01-01T00:00:00Z"
            },
            "signature": "0xfakebutpresent",
            "rules": []
        })
        .to_string()
        .as_bytes(),
    )
    .expect("parse signed bundle");

    let loader = BundleLoader::default();
    assert!(loader.verify(&bundle).is_ok());
}
