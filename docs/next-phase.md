# Next Phase: Phase 2 — Rust Server Workspace

Phase 1 (`phase-1-skeleton`) is complete. Phase 2 can start once that PR merges.

## Prerequisites for Phase 2

### Rust toolchain
- `rust-toolchain.toml` must pin `channel = "1.83.0"` with `components = ["clippy", "rustfmt"]`.
  This file is created in Phase 2 Step 2.0.
- `cargo` must be in PATH on the executing agent's host.
- `rustup` must be installed: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### Crate split (decided)
The `server/` workspace has four crates:
- `telemetry` — high-volume player event ingest; mirrors event schema from Phase 1.
- `ban-engine` — rule cache, signed-bundle deserializer skeleton.
- `license-server` — issue / revoke / verify route stubs.
- `api` — binary entrypoint; axum app, `/healthz`, GDPR-17 deletion stub.

### ONNX Runtime
- Dependency: `ort` crate (official ONNX Runtime Rust bindings).
- Pin the latest stable version at Phase 2 kick-off; record in `server/Cargo.toml` and here.
- CPU provider only for Phase 2; CUDA/CoreML deferred.

### Event schema contract
- `sdk/include/horkos/event_schema.h` (Phase 1 Step 1.6) is stable.
- Phase 2 telemetry crate must mirror each struct field-for-field in
  `server/telemetry/src/schema.rs` with a contract test that diffs field names
  and sizes against the C header. This diff is a merge gate.

### Legal floor
- `server/api/data-categories.md` must be created in Phase 2 Step 2.5 before
  any telemetry route accepts data.
- GDPR-17 deletion route (`DELETE /api/account/{id}/data`) ships as a `503` stub
  in Phase 2; the 202 + 30-day-SLA contract flips only after a durable persistence
  layer lands under `/tdd` in a follow-up phase.
