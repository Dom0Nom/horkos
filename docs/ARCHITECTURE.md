# Horkos — Codebase Architecture & Defensive Design

Single-file orientation for anyone (human or agent) landing in this repo cold.
What Horkos is, where everything lives, how data flows, and the defensive
principles every change must respect. Companion to `CLAUDE.md` (binding
guardrails) and `plans/horkos-ac-drm-scaffold.md` (the 5-phase blueprint).

## What this is

Horkos is a maximum-strength PC anti-cheat + DRM system: client-side sensors
on Windows / Linux / macOS (kernel and usermode), hardware attestation, an
LLVM obfuscation toolchain, and a Rust server that ingests telemetry, scores
it with statistical analyzers, and makes ban decisions. Console targets exist
as public-doc-shaped stubs only (no proprietary SDKs in the repo).

It is **defense-only**: every offensive technique in the repo lives in
`bypass-tests/` as a *test* that a detection must catch, never as shipped
capability.

## Top-level map

| Path | Role |
|---|---|
| `ac/` | Anti-cheat usermode core: self-integrity (`src/selfcheck/` — PE/text cross-view, IAT/GOT audits, retaddr provenance, W^X/PTE audits) and timing side-channel probes (`src/timing/`) |
| `attestation/` | Stable `Attestation.h` interface; backends: tpm2-tss (Win/Linux), CryptoKit/Secure Enclave (macOS), console stubs. The interface never changes; backends do |
| `bypass-tests/` | **Merge gate.** Adversarial tests per platform (`win/`, `linux/`, `macos/`, `cross/`, `server/`, `dma_hardware/`, network + timing subdirs). A change under any security folder without a corresponding bypass test is rejected |
| `console/` | `gdk_xbox/`, `nintendo_switch/`, `playstation/` — stubs whose signatures match public docs; every stub comments the documented function it maps to |
| `daemon/macos/` | Userspace daemon (bring-up path until ES entitlement lands): task-handle/ptrace/mmap/exception-port/thread/text integrity, codesign ops (`csops/`), device trust (`trust/`), input provenance (`input/`) |
| `dma_detect/` | DMA-cheat hardware forensics: PCIe config-space/BAR/MSI-X/option-ROM/ACS/TLP/hotplug audits, per-OS `backends/` |
| `docs/` | Research + design docs; `detection-catalog.md` (216 signals) and `impl-plans/*.md` (24 domains) are the detection source of truth |
| `drm/` | DRM/licence core (obfuscation-attributed paths) |
| `examples/` | `pc_basic` — minimal game integration |
| `kernel/win/` | KMDF boot-start driver: process/thread/image callbacks, ObRegisterCallbacks, SSDT/syscall/ETW integrity, callback-residency self-checks, driver whitelist (BYOVD defense). Builds only with WDK/MSVC |
| `kernel/linux/` | `bpf/` (LSM + tracepoints + fentry — primary; Steam Deck Game Mode requires eBPF), `lkm/` (optional, build-flag-gated, for self-hosted servers), `userspace/` loader + sensors |
| `kernel/macos/es/` | EndpointSecurity client (System Extension path, gated on Apple entitlement; `-DHORKOS_MACOS_ES=ON`). Never drops an ES auth event without a reply |
| `obfuscator/` | Standalone LLVM-19 pass plugin (CFF, opaque predicates, string encryption) + `lit` tests. Never shipped; heavy on the AC binary, attribute-opt-in (`hk_obfuscate`) on GAME init/licence/integrity/attestation only — never hot loops |
| `platform/` | The PAL. **The only place raw OS APIs are allowed** (plus `backends/` folders). Everything else uses `HK_PLATFORM_*` macros, never `_WIN32`/`__linux__`/`__APPLE__` |
| `sdk/` | Game-facing client SDK: wire schemas (`include/horkos/*.h`), usermode sensors (render-hook, input-provenance, net-timing probes), per-OS `backends/` |
| `server/` | Rust workspace (axum + tokio): `telemetry/` (ingest + analyzers), `ban-engine/` (fusion + ban path), `api/`, `license-server/` |
| `tests/unit/` | Host-runnable GoogleTest suites for pure-logic pieces (parsers, decoders, accumulators) |

## Data flow

```
client sensors (kernel + usermode, per OS)
   │  C99 wire structs: sdk/include/horkos/event_schema.h (+ per-domain
   │  headers: event_schema_macos.h, event_schema_cs.h, device_trust_schema.h,
   │  input_prov_schema.h, net_timing.h, render_hook_schema.h)
   ▼
per-tick JSON plane: server/telemetry/src/schema.rs::TickPayload  (v6)
   ▼
HTTP ingest (telemetry/src/lib.rs) — validate, stamp server_received_ts,
   per-player token bucket; forwarded via telemetry/src/sink.rs into
   ▼
pipeline shards (ban-engine/src/pipeline.rs — one tokio task per shard owns
   its players' sessions; consume-once tick↔snapshot merge-join)
   ▼
telemetry analyzers (server/telemetry/src/analyzers/ — signals scored
   individually, z-scored against honest-population baselines)
   +
game-state snapshot plane (snapshot_schema.h — server-internal, game server →
   AC server; the authoritative truth the client never sees)
   ▼
ban-engine fusion (ban-engine/src/fusion.rs) — fail-closed ban path; verdicts
   latch upward per session (Clean→Review→Ban, transitions only)
   ▼
decision store (ban-engine/src/store.rs — append-only audit records, JSONL
   via HORKOS_DECISION_LOG or in-memory) + GET /api/decisions/{player_id}
```

This pipeline runs end-to-end: `api::build_app()` spawns the shards and wires
ingest into them (`/healthz` turns 503 if a shard dies). The live snapshot
source is still the unimplemented shm ring (HK-UNCERTAIN ipc-contract);
until it lands, only fixture/test traffic exercises the gamestate analyzers,
and unpaired sessions surface as a Review-tier pairing-integrity anomaly.

Two wire planes, deliberately decoupled: the C99 kernel-event schema
(`HK_EVENT_SCHEMA_VERSION`) and the per-tick JSON stream
(`schema::SCHEMA_VERSION`, currently 6). Bump on every additive change.

## Defensive design principles

These recur everywhere; new code is expected to follow them.

1. **No single signal bans.** Analyzers emit `SuspicionEvent`s with z-scores;
   only ban-engine fusion across signals/sessions decides
   (`STANDALONE_BANNABLE` is a compile-checked policy constant).
2. **False-positive gating is structural, not tuned.** Statistical primitives
   in `telemetry/src/stats.rs`: population z-scores that return `None` on
   degenerate baselines (never a fabricated infinity), jitter-widened RTT
   budgets (a bursty-but-honest connection cannot present a false sub-budget
   peek), residual-vs-RNG correlation that scores a skilled human as clean by
   construction. Every analyzer excludes legitimately-knowable stimuli
   (audible, teammate-callout, in-frustum) before counting an event.
3. **Total functions over adversarial input.** Wire parsing is bound-checked;
   degenerate inputs (zero vectors, empty series, torn ring slots) return
   defined "no signal" results, never NaN/panic. Server: no `unwrap()` outside
   tests, `thiserror` errors, fully async on tokio (guardrail #8).
4. **Fail closed.** The ban path and ingest reject malformed/unknown-version
   payloads (400) rather than guessing.
5. **Bypass tests are the merge gate.** Every detection ships with the attack
   it must catch under `bypass-tests/`. 296 host-runnable ctest cases as of
   2026-06-09.
6. **Honest stubs.** Kernel/ES/signing APIs we could not verify are stubbed
   and marked `HK-UNCERTAIN` (315 sites), never guessed — a BSOD or a
   mis-documented security interface is worse than a delay. `HK-TODO(schema)`
   (121 sites) marks fields pending schema reconciliation. Grep for both
   before claiming a domain "done".
7. **Privacy is a declared surface.** Every collected field must be declared
   in `server/api/data-categories.md` in the same PR (guardrail #11);
   GDPR-13/17 are the legal floor, erasure route at
   `DELETE /api/account/{id}/data`.
8. **Obfuscation is scoped.** Broad on the AC binary; opt-in by
   `__attribute__((annotate("hk_obfuscate")))` on GAME init/licence/
   integrity/attestation symbols only. Never touches game hot loops.
9. **Layering is enforced.** Platform API only in `platform/`/`backends/`;
   kernel and userspace never share a translation unit; `Attestation.h` is
   frozen; console stubs carry public-doc citations.

## Build & verify matrix

| Component | Toolchain | Verifiable on macOS host? |
|---|---|---|
| `server/` workspace | cargo | **Yes** — `cargo build && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` |
| `tests/unit/`, bypass tests, `ac/`, `sdk/` host parts, `daemon/macos/`, `dma_detect/` (linux/macos) | CMake + AppleClang | **Yes** — fresh `cmake -S . -B <dir>` + `cmake --build` + `ctest` |
| `obfuscator/` | LLVM 19 + lit | **Yes** — `lit obfuscator/test` |
| `kernel/macos/es/` | clang `-fsyntax-only` (full build needs ES entitlement + `-DHORKOS_MACOS_ES=ON`) | Syntax only |
| `kernel/win/` + `sdk/src/backends/win/` | WDK/MSVC | **No** — build on the Windows box (`admin@192.168.178.80`) |
| `kernel/linux/bpf/`, `lkm/` | clang-bpf + libbpf + kernel headers | **No** — needs a Linux box / Steam Deck |

Never claim kernel code works until it compiled on its real target.

## Source-of-truth index

- Binding rules: `CLAUDE.md` (guardrails + locked decisions)
- Phase blueprint: `plans/horkos-ac-drm-scaffold.md`
- Detection catalog: `docs/detection-catalog.md` (216 signals), research in
  `docs/detection-research*.md`
- Per-domain implementation plans: `docs/impl-plans/*.md` (24)
- Wire formats: `sdk/include/horkos/event_schema.h` (+ per-domain headers),
  Rust mirror `server/telemetry/src/schema.rs`
- Data declarations: `server/api/data-categories.md`
- Platform deep-dives: `docs/windows-kernel-anticheat-techniques.md`,
  `docs/linux-ebpf-techniques.md`, `docs/macos-anticheat-deep-dive.md`,
  `docs/dma-detection.md`
- Latest run state: `docs/HANDOFF-impl-0609.md`

## State as of 2026-06-09

Phases 1–5 scaffolded; detection-implementation run committed on
`auto/impl-detections-0609` (commit `96761c6`). Host-verifiable subset is
green (cargo + 296 ctest + lit + ES syntax). Windows kernel/usermode and
Linux eBPF/LKM sources are **unverified** — no cross-toolchain on this host.
~19 of 24 implementation domains landed; the rest hit content-filter failures
and need re-runs (see the handoff). 315 `HK-UNCERTAIN` stubs await API
verification, the largest being ETW-TI (needs a PPL/ELAM-signed user-mode
consumer, not a kernel consumer).
