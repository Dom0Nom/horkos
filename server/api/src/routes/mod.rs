//! Role: Mounts all api-owned routes. Crate-foreign routers (telemetry,
//!       ban-engine, license-server) are composed in main.rs.
//! Target platforms: server.

pub mod account;
pub mod healthz;
