# Horkos

Maximum-strength cross-platform anti-cheat and performance-respecting DRM.

Client-side detection meets or exceeds Vanguard. Server-side behavioural ML beats EAC. DRM applies only to game init, licence, integrity, and attestation paths — never the hot loop.

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Skeleton, PAL, attestation interface, console stubs | Complete |
| 2 | Rust server workspace | Complete |
| 3 | Windows KMDF watchdog + SDK | Complete |
| 4 | Linux eBPF + macOS daemon/ES + DMA detection | Complete |
| 5 | LLVM 19 obfuscation passes + bypass tests + final review | Complete |

Per-platform build prerequisites are listed in the build matrix below; CI is
wired in `.github/workflows/ci.yml`. Remaining production gates (signing,
entitlements, console SDK access) are tracked in `docs/ship-readiness.md`.

## Build Matrix

| Platform | Kernel path | Build prerequisite |
|----------|-------------|-------------------|
| Windows 10/11 | KMDF driver (Phase 3) | WDK + MSVC |
| Linux | eBPF LSM + tracepoints (Phase 4) | clang-19, libbpf, bpftool |
| macOS | Userspace daemon; SysExt gated on entitlement (Phase 4) | Xcode CLT |

**Rust server** (Phase 2): `cargo build --release` from `server/`. Rust 1.83.0 pinned via `rust-toolchain.toml`.

**C++ clients + kernel**: CMake 3.20+, platform-conditional targets.

## Security Posture

All ban authority lives on the server. Client components detect and report; they never ban autonomously. Telemetry fields are declared in `server/api/data-categories.md`. GDPR Article 17 deletion route is present from Phase 2.
