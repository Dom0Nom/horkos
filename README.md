# Horkos

A from-scratch design and reference implementation of a maximum-strength,
cross-platform anti-cheat + DRM system, built as an engineering proof of
concept. It spans client kernel/usermode sensors (Windows, Linux, macOS),
hardware attestation, an LLVM obfuscation toolchain, and an async Rust server
that ingests telemetry, scores it, and owns every ban decision.

Defense-only: every offensive technique lives in `bypass-tests/` as a test a
detection must catch — never as shipped capability.

> PoC, not a product. The server, attestation crypto, licensing/DRM, and the
> statistical/ML scoring are implemented and verified on a host + Docker. The
> client kernel sensors are designed and scaffolded — they compile where a
> toolchain exists and are marked **UNVERIFIED** where they need real target
> hardware (a Windows WDK box, a Steam Deck kernel). Being explicit about what
> is and isn't verified is a design goal.

## Implemented and verified

Runs and is test-covered on a macOS host + Linux Docker:

- **Server pipeline** (`server/`, Rust + axum + tokio) — ingest → per-player
  sharded analysis → cross-signal fusion → latched, persisted bans. No single
  signal can ban (compile-checked invariant); fail-closed ingest; bounded
  everything. Green on macOS and Linux x86_64.
- **Behavioral scoring** — 9 game-state analyzers (z-scored vs. honest-population
  baselines), aim-kinematics segmenters, a lag-switch detector, and a trained
  **ONNX** model wired through fusion.
- **Hardware attestation** — server-side TPM quote verifier (real **tpm2-tss**
  Linux backend, verified against swtpm) and a real **Secure Enclave** macOS
  backend (verified on-device).
- **Licensing + DRM** — Ed25519 licence tokens with hardware binding, revocation
  and expiry; a libsodium DRM verifier; a signed-rule-bundle verifier.
- **Live snapshot transport** — a seqlock shared-memory ring with a POSIX reader,
  round-trip tested including torn-frame recovery.

## Scaffolded / target-bound

Written and compiled where possible, not yet verified on real hardware:

- **Windows KMDF driver** + usermode sensors — not compiled on a WDK box.
- **Linux eBPF** (33 programs) + loader + LKM — 31/33 eBPF objects + the LKM
  compile clean in Docker; BPF-LSM attach needs a `CONFIG_BPF_LSM` kernel.
- **Console backends** — public-doc-shaped stubs only; no proprietary SDKs.
- **LLVM obfuscation passes** — standalone LLVM-19 plugin, never shipped.

## Quickstart

```sh
# Rust server (most complete surface)
cd server && cargo test --workspace && cargo build --release

# C++ host test suite
cmake -S . -B build && cmake --build build --target hk_unit_tests && (cd build && ctest)

# Train the aim model
python3 server/ml/train_aim_model.py
```

Run the server: `cargo run -p api` (binds `0.0.0.0:8080`; configured via
`HORKOS_BIND`, `HORKOS_DECISION_LOG`, `HORKOS_AIM_MODEL`, `HORKOS_SNAPSHOT_RING`).

## Design

`docs/ARCHITECTURE.md` is the orientation file — directory map, the two wire
planes, data flow, and the defensive design principles. Headline: **no single
signal bans**; analyzers emit z-scored suspicion, and only server-side fusion
decides, with structural false-positive gating throughout. All ban authority is
server-side; client components detect and report, never ban autonomously.

## License

MIT — see `LICENSE`.
