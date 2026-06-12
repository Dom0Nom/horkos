//! Role: Horkos API binary entrypoint. Owns the tokio runtime and tracing
//! subscriber. Only file in this crate that may use `anyhow` (per
//! CLAUDE.md guardrail #8 — library code uses `thiserror`).
//!
//! Target platforms: server (any tokio-supported OS).

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let bind_addr: SocketAddr = std::env::var("HORKOS_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("HORKOS_BIND must be a valid socket address")?;

    // build_app spawns the analysis pipeline (ingest -> analyzers -> fusion ->
    // persisted decisions); the handle keeps the liveness flag and decision
    // map alive for the process lifetime.
    let (app, _pipeline) = api::build_app().context("failed to build application")?;

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    tracing::info!(%bind_addr, "horkos-api listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum server crashed")?;

    tracing::info!("horkos-api shutdown complete");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("HORKOS_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,axum=info,tower_http=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        // Degrade rather than panic if the handler cannot be installed: this
        // future simply never resolves, leaving the other shutdown signal live.
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!("failed to install ctrl-c handler: {e}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("failed to install SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c    => tracing::info!("ctrl-c received, shutting down"),
        _ = terminate => tracing::info!("SIGTERM received, shutting down"),
    }
}
