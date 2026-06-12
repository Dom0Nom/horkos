# Horkos

A from-scratch, cross-platform anti-cheat + DRM system. Client kernel/usermode
sensors (Windows, Linux, macOS), hardware attestation, an LLVM obfuscation
toolchain, and an async Rust server that ingests client telemetry, scores it,
and owns the ban decision.

Proof of concept — untested, not verified on real target hardware, not production code.

## Quickstart

```sh
# Rust server — build and run (binds 0.0.0.0:8080)
cd server && cargo build --release && cargo run -p api

# C++ host components
cmake -S . -B build && cmake --build build
```

See `docs/ARCHITECTURE.md` for the directory map and design.

## License

MIT — see `LICENSE`.
