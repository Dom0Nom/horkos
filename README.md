# Horkos

A from-scratch **design and reference implementation of a maximum-strength,
cross-platform anti-cheat + DRM system**, built as an engineering proof of
concept. Horkos spans client-side kernel/usermode sensors on Windows, Linux and
macOS, hardware attestation, an LLVM obfuscation toolchain, and an async Rust
server that ingests telemetry, scores it, and owns every ban decision.

It is **defense-only**: every offensive technique in the tree lives in
`bypass-tests/` as a test a detection must catch — never as shipped capability.

> **Scope note.** This is a PoC, not a shipping product. The server, the
> attestation crypto, the licensing/DRM paths and the statistical/ML scoring are
> implemented and verified on a host + Docker (details below). The client kernel
> sensors are designed and scaffolded; they compile where a toolchain is
> available (eBPF in Docker) and are explicitly marked **UNVERIFIED** where they
> need their real target (a Windows WDK box, a Steam Deck kernel). Honesty about
> what is and isn't verified is a design goal — see `docs/HANDOFF-notimpl-0610.md`.

## What's implemented and verified

These run and are covered by tests on a macOS host + Linux Docker:

- **End-to-end server pipeline** (`server/`, Rust + axum + tokio) — telemetry
  ingest → per-player sharded analysis → cross-signal fusion → latched,
  persisted ban decisions. No single signal can ban (structural, compile-checked
  invariant); fail-closed ingest; bounded everything (DoS gates). Verified green
  on macOS **and** Linux x86_64.
- **Behavioral scoring** — 9 game-state-knowledge analyzers (z-scored against
  honest-population baselines), aim-kinematics segmenters, a lag-switch detector,
  and a real **ONNX** model (`server/ml/train_aim_model.py`) wired through the
  fusion path.
- **Hardware attestation** (`attestation/`, `server/attestation-verify/`) —
  a server-side TPM quote verifier, a real **tpm2-tss** Linux backend verified
  end-to-end **against swtpm**, and a real **Secure Enclave** macOS backend
  verified end-to-end **on-device**. Both a real TPM quote and a real SE
  signature round-trip through the verifier.
- **Licensing + DRM** — Ed25519-signed licence tokens with hardware binding,
  revocation and expiry (`server/license-server/`); a libsodium Ed25519 DRM
  licence verifier (`drm/`); and a real Ed25519 signed-rule-bundle verifier in
  the ban engine.
- **Live snapshot transport** — a seqlock shared-memory ring (`snapshot_schema.h`)
  with a POSIX reader, round-trip tested against a real `shm_open` producer
  including torn-frame recovery.
- **Wire schema** — a frozen C99 event schema with host-checked size pins, plus
  a large-record drain plane for oversized payloads.

## What's scaffolded / target-bound

Designed and written, compiled where possible, but not verified on the real
target (and not claimed to work until it is):

- **Windows KMDF driver** (`kernel/win/`) + Windows usermode sensors
  (`sdk/src/backends/win/`) — never compiled on a WDK box.
- **Linux eBPF** (`kernel/linux/bpf/`, 33 programs) + loader + LKM — **first
  compiled in Docker** (31/33 eBPF objects + the LKM C compile clean; see
  `docs/linux-build-results-0611.md`), but BPF-LSM attach + module load need a
  `CONFIG_BPF_LSM` kernel (e.g. SteamOS).
- **Console backends** (`console/`) — public-doc-shaped stubs only; no
  proprietary SDKs in the repo.
- **LLVM obfuscation passes** (`obfuscator/`) — standalone LLVM-19 plugin, never
  shipped in the binary.

## How it's verified

| Surface | Where | Result |
|---|---|---|
| Rust server workspace | macOS host + `cargo test` | green |
| Rust server workspace | Linux x86_64 (Docker) | green |
| C++ host logic (parsers, decoders, DRM, schema) | macOS + GoogleTest/CTest | green (disabled bypass tests pending enforcement mode) |
| eBPF objects | Docker (clang-bpf + kernel BTF) | 31/33 compile |
| LKM | Docker (kernel headers) | C compiles clean |
| TPM attestation | Docker + **swtpm**, end-to-end | quote verifies |
| Secure Enclave attestation | this **Mac**, end-to-end | signature verifies |

## Quickstart

```sh
# Rust server (the most complete surface)
cd server && cargo test --workspace && cargo build --release

# C++ host test suite (pure-logic pieces across all domains)
cmake -S . -B build && cmake --build build --target hk_unit_tests
cd build && ctest

# Train the aim model (numpy + onnx)
python3 server/ml/train_aim_model.py
```

Run the server: `cargo run -p api` (binds `0.0.0.0:8080`; `HORKOS_BIND`,
`HORKOS_DECISION_LOG`, `HORKOS_AIM_MODEL`, `HORKOS_SNAPSHOT_RING` configure it).

## Architecture & design

`docs/ARCHITECTURE.md` is the orientation file: the directory map, the two wire
planes and data flow (client sensors → telemetry analyzers → ban-engine fusion),
and the nine defensive design principles. The headline principle: **no single
signal bans** — analyzers emit z-scored suspicion events, and only server-side
fusion across signals and sessions decides, with structural false-positive
gating throughout.

## Security posture

All ban authority is server-side. Client components detect and report; they
never ban autonomously. Telemetry fields are declared in
`server/api/data-categories.md`. A GDPR Article-17 deletion route is present.

## Build matrix

| Platform | Path | Toolchain |
|---|---|---|
| Server | `server/` | Rust 1.95 (`rust-toolchain.toml`) |
| C++ host tests | `tests/unit/` | CMake 3.20+, a C++17 compiler, libsodium |
| Windows kernel + sensors | `kernel/win/`, `sdk/src/backends/win/` | WDK + MSVC (Windows box) |
| Linux eBPF/LKM | `kernel/linux/` | clang-bpf, libbpf, bpftool, kernel headers |
| macOS daemon/ES | `daemon/macos/`, `kernel/macos/es/` | Xcode CLT (ES gated on entitlement) |

## License

MIT — see `LICENSE`.
