# Next Phase: Phase 1 in progress

Phase 1 is currently being executed. When it merges, this file will be updated
with Phase 2 prerequisites.

## Phase 2 prerequisites (to be confirmed at Phase 1 merge)

- Rust toolchain pinned: `rust-toolchain.toml` created in Phase 1 skeleton (or Phase 2 Step 2.0).
- Crate split decided: telemetry, ban-engine, license-server, api.
- `cargo` available in PATH on the executing agent's host.
- ONNX Runtime via `ort` crate: version to pin is the latest stable at Phase 2 kick-off; record the chosen version in this file.
- Phase 1 SDK shapes (`sdk/include/horkos/event_schema.h`, `attestation/Attestation.h`, `drm/include/horkos/drm.h`, `ac/include/horkos/ac.h`) are stable before Phase 2 starts — Phase 2 Rust structs will mirror the C99 event schema.
