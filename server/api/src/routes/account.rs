//! src/routes/account.rs
//!
//! Role: GDPR Article 17 deletion route. Phase 2 returns 503 + Retry-After:
//! 86400 so clients can compile against the URL surface but no false
//! 202+SLA promise is made before durable persistence lands.
//!
//! See risk register entry R10 in plans/horkos-ac-drm-scaffold.md and the
//! flip-to-202 follow-up phase named in docs/gdpr-17-rollout.md.
//!
//! Target platforms: server.

use axum::{
    extract::Path,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::delete,
    Json, Router,
};
use serde_json::json;

const RETRY_AFTER_SECONDS: u32 = 86_400;

pub fn router() -> Router {
    Router::new().route("/api/account/{id}/data", delete(delete_account_data))
}

#[tracing::instrument(skip_all, fields(account_id = %id))]
async fn delete_account_data(Path(id): Path<String>) -> Response {
    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "bad_request", "reason": "id is empty" })),
        )
            .into_response();
    }

    tracing::warn!(
        target: "horkos::gdpr17",
        account_id = %id,
        "GDPR-17 deletion requested but persistence layer not yet provisioned"
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&RETRY_AFTER_SECONDS.to_string())
            .expect("retry-after seconds always render as ASCII"),
    );

    (
        StatusCode::SERVICE_UNAVAILABLE,
        headers,
        Json(json!({
            "status": "unavailable",
            "reason": "deletion service not yet provisioned"
        })),
    )
        .into_response()
}
