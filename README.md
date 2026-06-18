# Horkos

A from-scratch, cross-platform anti-cheat + DRM system. Client kernel/usermode
sensors (Windows, Linux, macOS), hardware attestation, an LLVM obfuscation
toolchain, and an async Rust server that ingests client telemetry, scores it,
and owns the ban decision.

Proof of concept: untested, not verified on real target hardware, not production code.

## Status

Personal research **proof of concept**. Nothing here has been tested or verified on real target hardware, and none of it is production-ready. Where individual commit messages say "tested", that means local compilation or unit-level checks only; treat the project as untested end-to-end. Provided as-is, no warranty.

## Quickstart

```sh
# Rust server: build and run (binds 0.0.0.0:8080)
cd server && cargo build --release && cargo run -p api

# C++ host components
cmake -S . -B build && cmake --build build
```

See `docs/ARCHITECTURE.md` for the directory map and design.

## License

MIT. See `LICENSE`.