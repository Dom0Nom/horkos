# Horkos — Maximum-Strength Cross-Platform AC + DRM Scaffold

**Objective.** Build the strongest PC anti-cheat stack on the market — meet or beat Vanguard for client-side detection, beat EAC for server-side behavioural ML — and ship a performance-respecting DRM layer that does not touch the game's hot loop. Five phases, each one PR, executed PC-first, console-ready.

**Plan owner.** dominic
**Repo.** `/Users/dominic/horkos` (not yet under git — Phase 1 Step 1.0 inits it)
**Target remote.** `github.com/Dom0Nom/horkos` (private; created in Step 1.0)
**Default branch.** `main`
**Model split.** Phase planning: Opus 4.7. Phase execution: Sonnet 4.6.
**Persistence.** `/save-session` at end of each phase. `/resume-session` to restart.
**Scope discipline.** Stubs and module comments in scaffolding sessions; logic lands in named subsequent phases under `/tdd` where testable.

---

## Locked decisions (do not relitigate without a Mutation Protocol entry)

1. **Server stack:** Rust + axum + tokio + ONNX Runtime via the `ort` crate. Chosen for tail-latency determinism in the ban path.
2. **Windows kernel:** KMDF (not WDM). Boot-start service. Driver whitelist enforced (BYOVD defense).
3. **Linux kernel:** eBPF (LSM + tracepoints + uprobes) primary; LKM behind a build flag for self-hosted servers and non-Deck distros. Steam Deck Game Mode requires eBPF.
4. **macOS kernel:** System Extension + EndpointSecurity gated on Apple entitlement approval. Userspace daemon ships as bring-up path; SysExt swap when entitlement lands.
5. **LLVM toolchain:** LLVM 19. Heavy obfuscation across the AC binary; light, attribute-opt-in obfuscation on GAME init/licence/integrity/attestation paths only. Standalone build tool, never shipped.
6. **Attestation:** `tpm2-tss` for Windows + Linux behind a single `Attestation` C++ interface; CryptoKit / Secure Enclave on macOS; documented stubs for console SDKs.
7. **Console SDKs (NintendoSDK, GDK, PlayStation):** proprietary, not present. Stubs only with public-doc-shaped signatures, every stub commented with the documented function it maps to.

---

## Pre-flight observations (dev machine: macOS Darwin 24.6.0)

| Probe | Result | Phase impact |
|---|---|---|
| Working dir | `/Users/dominic/horkos` exists, only `.claude/` inside | Phase 1.0 inits repo and structure |
| Git | Not a repo | Phase 1.0 `git init` + `gh repo create` |
| GitHub CLI | Authenticated as `Dom0Nom` | Remote creation OK |
| clang | Apple clang 17 | Phase 1 macOS PAL build OK |
| cmake | 4.0.2 | Phase 1 superbuild OK |
| Rust | rustup + 1.83.0 + clippy + rustfmt installed (x86_64-apple-darwin) | OK |
| LLVM | `llvm@19` 19.1.7 + `llvm@20`; pin Phase 5 to `$(brew --prefix llvm@19)` | OK |
| tpm2-tss | Not installed | Phase 1 attestation stubs OK; Phase 4+ real backend needs `brew install tpm2-tss` (linux-only on host) and Linux CI |
| FileCheck | Bottled with `llvm@19` at `$(brew --prefix llvm@19)/bin/FileCheck` | OK |
| lit | **Not bottled with `llvm@19`** | Phase 5 prerequisite: `pip install lit` (or `pipx install lit`) |
| WDK | Not on this machine | Phase 3 needs Windows VM or CI runner |

**Phase 0 checklist (do once before Phase 1 starts execution):**
- [ ] `brew install llvm@19` and pin its `bin/` in CMake `LLVM_DIR` for the obfuscation tool only.
- [ ] `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` then `rustup install 1.83.0 && rustup default 1.83.0`. Pin via `rust-toolchain.toml` (added in Phase 2 Step 2.0).
- [ ] **Start EV code-signing cert procurement now.** DigiCert / Sectigo lead time is 1–4 weeks plus a hardware token. The cert is required for Phase 3 production driver signing and any external distribution. Test-signing is sufficient for in-VM Phase 3 verification, but the cert must be procured in parallel. (See R11.)
- [ ] Windows VM or CI runner provisioned with current WDK before Phase 3 kicks.
- [ ] Plan a Linux CI image with `tpm2-tss-dev`, `libbpf-dev`, `clang-19`, `bpftool` for Phase 4.

---

## Cross-cutting guardrails (binding from Phase 1)

These mirror `CLAUDE.md` and act as a merge-time review checklist on every PR. The reviewer subagent uses them as the primary anti-pattern catalog.

1. **No platform API outside `platform/` or a `backends/` folder.** All conditional code uses `HK_PLATFORM_WINDOWS`, `HK_PLATFORM_LINUX`, `HK_PLATFORM_MACOS`, never raw `_WIN32` / `__linux__` / `__APPLE__`.
2. **No proprietary SDK headers in the repo.** Console folders are stubs whose signatures match public-doc shapes; every stub has a comment naming the documented function it maps to.
3. **Module comment on every new file.** Role, target platform(s), interface header it implements or declares.
4. **Kernel and userspace code never share a translation unit.**
5. **Kernel C uses safe string functions exclusively.** Every `NTSTATUS` or kernel return is checked.
6. **Linux kernel code (LKM and eBPF) compiles `-Wall -Wextra -Werror` at the kernel's warning level.**
7. **macOS System Extension never drops an ES event without a reply.**
8. **Server is fully async on tokio.** No blocking calls on async threads. `thiserror` for error types. No `unwrap()` outside tests.
9. **LLVM passes never touch the GAME binary's hot-loop functions.** Opt-in by `__attribute__((annotate("hk_obfuscate")))` only on init/licence/integrity/attestation symbols. The AC binary may be obfuscated broadly.
10. **`Attestation.h` is the stable interface.** Backends change; the interface does not.
11. **Adding a telemetry field requires updating `server/api/data-categories.md` in the same PR.** Reviewer rejects undeclared fields.
12. **`bypass-tests/` are a merge gate.** A change under any security folder without a corresponding bypass test is rejected.
13. **When uncertain about a kernel API, stop and flag it.** A BSOD is worse than a delay.
14. **No business logic in scaffolding sessions.** Stubs and module comments only. Logic lands in subsequent phases under `/tdd` where testable.

---

## Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Apple denies `endpoint-security.client` entitlement | Medium | High — no SysExt path on macOS | Userspace daemon ships first; SysExt target gated by `HORKOS_MACOS_ES`. |
| R2 | WDK signing process blocks Phase 3 verify | Medium | High | Test-signing instructions in repo; real signing certificate procurement is a prerequisite for ship, not for Phase 3 acceptance. |
| R3 | UEFI/IOMMU firmware misreports DMA state (2025 CVE class) | Confirmed | Medium | Detect-and-report only; never trust firmware claim alone; cross-check with PCIe enumeration. |
| R4 | BYOVD whitelist drift | High | Medium | Server-pushed signed bundles, weekly rotation. Local cache short-lived. |
| R5 | LLVM 19 vs LLVM 20 upstream API drift | Medium | Medium | Phase 0 pins llvm@19 explicitly. If brew drops llvm@19 before Phase 5, raise Mutation Protocol entry. |
| R6 | Steam Deck Game Mode disallows custom kernel modules | Confirmed | Medium | eBPF is the deployable Linux path; LKM is build-flagged for self-host only. |
| R7 | Console SDK access gated by NDA / dev account | Confirmed | Low (this scaffold) | Stubs only this scaffold; real console work is a separate, gated initiative. |
| R8 | Kernel BSOD during driver bring-up | Medium | High (dev productivity) | All kernel work in a snapshot-ready Windows VM; bring-up uses `verifier.exe`. |
| R9 | Hypervisor refusal breaks legitimate Microsoft-attested vTPM scenarios | Low | High (player-facing) | Allow vTPM via TPM PCR policy on day one; document the exception. |
| R10 | GDPR-17 deletion route bug exposes data after delete | Low | Catastrophic | Phase 2 lands the route as a fail-closed `503 + Retry-After` stub. The 202 + 30-day-SLA contract flips on only after the durable persistence layer lands under `/tdd` in a follow-up phase. The route is never silently optimistic. |
| R11 | EV signing certificate procurement lead time | Confirmed | High | DigiCert / Sectigo EV certs take 1–4 weeks and require a hardware token. Procurement starts at Phase 0, not Phase 3. Test-signing is fine for Phase 3 acceptance; ship requires the real EV cert. |
| R12 | Microsoft Hardware Dev Center / WHQL submission lead time | Confirmed | High | Production driver requires WHQL attestation submission. Not a Phase 3 blocker, but the submission package (driver + INF + signed catalog) is a deliverable before any external alpha. |
| R13 | Phase 3 / Phase 5 may not fit one PR for Sonnet 4.6 | High | Medium | Each phase carries a "Split decision" gate at start of execution: if the agent estimates >2 sessions of focused work, split into 3a/3b or 5a/5b along the suggested seam. The split is recorded in the Mutation log but does not require Locked-Decision change. |

---

## Dependency graph (phase-level)

```
Phase 0 (prereq)
       │
       ▼
Phase 1: Skeleton + PAL + PC platforms
       │
       ├──────────────────────────────┐
       ▼                              ▼
Phase 2: Rust server workspace        Phase 3: Windows KMDF + SDK wiring
       │                              │
       └─────────┬────────────────────┘
                 ▼
       Phase 4: Linux eBPF + macOS daemon
                 │
                 ▼
       Phase 5: LLVM 19 passes + consoles + bypass-tests + final review
```

Phase 2 and Phase 3 are **independent** after Phase 1 lands. Phase 2 needs Rust toolchain only; Phase 3 needs Windows + WDK only. They may run in parallel sessions if a Windows VM is available; otherwise execute serially. Phase 4 depends on the SDK shape settling at end of Phase 3 (the IOCTL bridge surface and the SDK C-API need to be stable before Linux/macOS daemons mirror the same surface). Phase 5 depends on all three OS backends.

---

## Phase mutation protocol

Steps may be split, inserted, skipped, reordered, or abandoned. Every mutation is recorded inline in this file under a `## Mutation log` section appended at the bottom, dated, signed (commit SHA that contains the change), and stating which Locked Decision (if any) it touches. Locked Decisions never silently change — a mutation that touches one must explicitly say so and provide the new rationale.

---

# Phase 1 — Skeleton + PAL + PC platforms

**Objective.** Repo scaffold; `platform.h` fully implemented across Windows / Linux / macOS; `drm/` and `attestation/` interfaces with backend stubs that compile; console folders are README-only stubs; root `CMakeLists.txt` with platform-conditional targets; `tests/unit` sentinel test passing; `/verify` configures and builds on Linux + macOS locally.

**Owner model.** Sonnet 4.6.
**Branch.** `phase-1-skeleton`.
**One PR.**

## Step 1.0 — Repo init + remote + governance docs

**Self-contained context brief.** A fresh agent starting here knows: the working dir is `/Users/dominic/horkos`, currently empty except `.claude/`. It is not a git repo. The remote does not exist. Goal of this step: make it a private GitHub repo under `Dom0Nom/horkos`, add `.gitignore`, top-level `README.md` (one paragraph + phase status table), top-level `CLAUDE.md` (verbatim from the user's directives in the project prompt — copy them in, do not paraphrase), `LICENSE` (proprietary, all rights reserved — this is a closed-source AC), `docs/` directory with `next-phase.md` (initially "Phase 1: in progress").

**Tasks.**
- `git init -b main`
- Write `.gitignore` (CMake build dirs, `target/`, `.DS_Store`, IDE files, `*.pdb`, `*.exp`, `*.lib`, `*.sys`, `*.cer`, `*.pfx`, `*.bpf.o`, `*.skel.h`)
- Write `README.md` with: project tagline, security posture statement, phase status table (1 in progress, 2–5 not started), build matrix.
- Write `CLAUDE.md` containing **verbatim** the 14 numbered guardrails under the "Cross-cutting guardrails" section of this plan (do not paraphrase, do not renumber), followed by the Locked Decisions block (also verbatim from this plan), followed by a final section "On uncertainty" that tells future agents to stop and flag rather than guess on kernel APIs, ES auth handling, or signing flows. The agent executing this step should copy from this plan file directly — the source of truth is `plans/horkos-ac-drm-scaffold.md`.
- Write `LICENSE` (proprietary).
- Write `docs/next-phase.md` (Phase 2 prerequisites: Rust toolchain pinned, server crate split decided).
- `gh repo create Dom0Nom/horkos --private --source=. --remote=origin --push` after first commit.

**Verification.** `git log --oneline` shows one commit; `gh repo view` shows the private repo; CLAUDE.md present and contains the verbatim directives.

**Exit criteria.** Repo exists, remote pushed, governance docs in place.

**Rollback.** `gh repo delete Dom0Nom/horkos --yes` and `rm -rf .git`. No code committed yet.

## Step 1.1 — `platform/` module: macros, header, three backends

**Self-contained context brief.** All platform-conditional code in this codebase routes through `platform/platform.h`. A new agent should read CLAUDE.md directive #1 first. The header defines `HK_PLATFORM_WINDOWS`, `HK_PLATFORM_LINUX`, `HK_PLATFORM_MACOS` macros (set automatically based on `_WIN32` / `__linux__` / `__APPLE__` at exactly one place — here — never elsewhere). It declares a small set of platform abstractions: `hk::platform::page_size()`, `hk::platform::process_id_t`, `hk::platform::module_handle_t`, `hk::platform::is_debugger_attached()`. The three backends (`platform_win.cpp`, `platform_linux.cpp`, `platform_macos.cpp`) each implement these. CMake conditionally compiles only the matching backend.

**Tasks.**
- `platform/platform.h` with the macro block, types, and function declarations. Module comment at top: role + target platforms + this is the platform interface header.
- `platform/platform_win.cpp` — uses `<windows.h>`, returns `GetCurrentProcessId()`, `IsDebuggerPresent()` (deliberately weak for Phase 1; real anti-debug lands in a later phase).
- `platform/platform_linux.cpp` — uses `<sys/syscall.h>`, reads `/proc/self/status` `TracerPid:` field for debugger detection.
- `platform/platform_macos.cpp` — uses `sysctl(KERN_PROC_PID)` `P_TRACED` bit for debugger detection.
- CMake: `add_library(hk_platform STATIC ${platform_src})` where `${platform_src}` is selected by `if(WIN32) elseif(APPLE) elseif(UNIX)`.

**Verification.** Each backend compiles standalone for its platform. `nm` / `dumpbin` shows the four expected symbols.

**Exit criteria.** `platform.h` is the single source of platform truth in the codebase. A grep for `_WIN32` outside `platform.h` returns zero results in `platform/`.

**Rollback.** Delete `platform/`, revert CMakeLists changes.

## Step 1.2 — `attestation/` interface + Win/Linux/macOS backend stubs

**Self-contained context brief.** Attestation is the stable interface that Locked Decision #6 says never changes. A new agent should read CLAUDE.md directive #10. This step defines `attestation/Attestation.h` (a pure-virtual C++ class with `create()` factory) and three backend stubs that compile but return `AttestationStatus::NotImplemented`. The TPM-backed Windows / Linux backends will use `tpm2-tss` in a later phase; for Phase 1 they are link-stub headers + `.cpp` files that compile without `tpm2-tss` present. The macOS backend will use CryptoKit / Secure Enclave; for Phase 1 it is also a stub.

**Tasks.**
- `attestation/Attestation.h` — interface: `enum class AttestationStatus { Ok, NotImplemented, HardwareUnavailable, PolicyRejected }; struct AttestationQuote { ... }; class Attestation { public: virtual ~Attestation() = default; virtual AttestationStatus quote(...) = 0; static std::unique_ptr<Attestation> create(); };`
- `attestation/backends/win/AttestationTpm2Win.cpp` — stub returning `NotImplemented`. Module comment names this as the Phase 4+ tpm2-tss backend.
- `attestation/backends/linux/AttestationTpm2Linux.cpp` — same.
- `attestation/backends/macos/AttestationSecureEnclave.cpp` — same.
- `attestation/backends/console/{nintendo,gdk,playstation}/Attestation*.cpp` — stub returning `NotImplemented` with a comment pointing at the public-doc-named function on each console.
- `Attestation::create()` selects the backend via `HK_PLATFORM_*`.

**Verification.** `attestation/` compiles into `hk_attestation` static library. A unit test (`tests/unit/test_attestation_create.cpp`) constructs the create-default backend and asserts `quote()` returns `NotImplemented`.

**Exit criteria.** Interface header is final shape. Backends compile. Switch from stub to real TPM is a swap of the `.cpp`, not a header change.

**Rollback.** Delete `attestation/`.

## Step 1.3 — `drm/` interface + `ac/` interface stubs

**Self-contained context brief.** DRM and AC are separate static libraries (Locked Decision: DRM is performance-respecting, applies only to game init/licence/integrity/attestation; AC is the heavy client). A new agent should read CLAUDE.md directives #9 and #14. This step lays in the headers and minimal stubs. Real logic lands in Phase 3 (AC) and a later phase (DRM checks under `/tdd`).

**Tasks.**
- `drm/include/horkos/drm.h` — C API: `int drm_validate(const drm_context_t* ctx);`, `drm_context_t` opaque.
- `drm/src/drm.cpp` — `drm_validate` returns `HK_DRM_NOT_IMPLEMENTED`.
- `ac/include/horkos/ac.h` — C API: `int ac_start(const ac_config_t* cfg);`, `int ac_stop(void);`.
- `ac/src/ac.cpp` — both return `HK_AC_NOT_IMPLEMENTED`.
- Both libraries depend on `hk_platform` only — not on each other.

**Verification.** `drm/`, `ac/` compile. Headers are include-clean (no `windows.h` leak through).

**Exit criteria.** SDK consumers can `#include <horkos/drm.h>` and `<horkos/ac.h>` and get pure-C surface.

**Rollback.** Delete `drm/`, `ac/`.

## Step 1.4 — `console/` README-only stubs

**Self-contained context brief.** Console SDKs are proprietary and are not present. Per CLAUDE.md directive #2 and Locked Decision #7, this scaffold ships only directory placeholders with `README.md` describing the public-doc shape of each platform's attestation/integrity surface. Real headers are added under NDA in a future, separately-gated phase.

**Tasks.**
- `console/nintendo_switch/README.md` — describes the public NintendoSDK shape (account/identity, hidden-process detection per public docs).
- `console/gdk_xbox/README.md` — Microsoft Game Development Kit public-doc shape (XGameRuntime, attestation surface).
- `console/playstation/README.md` — public-doc shape.
- Each README ends with the literal sentence: "Implementation requires NDA / dev-account access and is intentionally absent from this repository."

**Verification.** Directories exist. `git ls-files console/` shows only `README.md` files.

**Exit criteria.** Console scope is documented and bounded; reviewer cannot confuse "missing" with "todo".

**Rollback.** Delete `console/`.

## Step 1.5 — `tests/unit` sentinel + CTest wiring

**Self-contained context brief.** A new agent should know: this project uses GoogleTest fetched via CMake `FetchContent`, pinned to **tag `v1.17.0`**. CTest discovery via `gtest_discover_tests`. Tests live under `tests/unit/` with one `.cpp` per test target.

**Tasks.**
- Top-level `CMakeLists.txt` adds `enable_testing()` and `add_subdirectory(tests)`.
- `tests/CMakeLists.txt` fetches GoogleTest, defines `add_subdirectory(unit)`.
- `tests/unit/CMakeLists.txt` defines `hk_unit_tests` target linking `hk_platform`, `hk_attestation`, `hk_drm`, `hk_ac`, GTest.
- `tests/unit/test_sentinel.cpp` — single test asserting `1 + 1 == 2`. Module comment notes it is the build-system smoke test, not a real test.
- `tests/unit/test_attestation_create.cpp` — already drafted in Step 1.2.
- `gtest_discover_tests(hk_unit_tests)`.

**Verification.** `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure` succeeds on macOS and Linux.

**Exit criteria.** `ctest` returns 0. Adding a new unit test is a single-line `add_executable` addition.

**Rollback.** Delete `tests/`, revert CMakeLists.

## Step 1.6 — Shared event schema seed (`sdk/include/horkos/event_schema.h`)

**Self-contained context brief.** Phase 2 (Rust telemetry) and Phase 3 (kernel IOCTL) describe the *same* event payloads from opposite sides of the wire. If those two surfaces drift, every cross-platform test misses real bugs. Phase 1 lands the seed: a single C99 header that is the source of truth for event field names, types, and sizes. Phase 2 mirrors it via hand-written serde structs guarded by a contract test that diffs field names and sizes against the C header. Phase 3's IOCTL header `#include`s it directly. The header is plain C99 with fixed-width types (`uint32_t`, `uint64_t`, `int32_t`) and no platform headers — never `<windows.h>`, never `<linux/types.h>`.

**Tasks.**
- `sdk/include/horkos/event_schema.h` — defines `enum hk_event_type`, `struct hk_event_header { uint32_t version; uint32_t type; uint64_t timestamp_ns; uint32_t payload_bytes; }`, plus a small set of placeholder payload structs (`hk_event_process_create`, `hk_event_image_load`, `hk_event_handle_open`). Module comment names this as the wire-format source of truth.
- `static_assert(sizeof(struct hk_event_header) == 24, "...");` and matching asserts on each payload.
- `tests/unit/test_event_schema_sizes.cpp` asserts the same sizes from C++ side.
- `docs/event-schema.md` — describes versioning rules: every field addition bumps `version`, no field renames, deprecated fields stay reserved.

**Verification.** `static_assert`s pass on Linux + macOS. Test asserts the documented sizes.

**Exit criteria.** Phase 2 and Phase 3 both have a stable contract to mirror.

**Rollback.** Delete `sdk/include/horkos/event_schema.h` and the test.

## Step 1.7 — `docs/next-phase.md` updated for Phase 2

**Tasks.** Document Phase 2 prerequisites: Rust toolchain pinned via `rust-toolchain.toml`; crate split decided (telemetry, ban-engine, license-server, api); `cargo` available in PATH; ONNX Runtime via `ort` crate version pinned.

**Exit criteria.** `docs/next-phase.md` reads as the brief a fresh agent would pick up cold.

## Phase 1 verification gate

- [ ] `cmake -S . -B build -G Ninja`
- [ ] `cmake --build build`
- [ ] `ctest --test-dir build --output-on-failure`
- [ ] No raw platform macros outside `platform/platform.h`: `rg -n '\b(_WIN32|__linux__|__APPLE__)\b' --type cpp --type c -g '!platform/platform.h'` returns empty across the entire repo. Backends in `platform_*.cpp` are selected by CMake `if(WIN32)` etc., not by `#ifdef _WIN32` — they always compile when the host matches.
- [ ] `find . -path ./build -prune -o -type f -name '*.cpp' -print -o -name '*.h' -print | xargs head -1 | grep -c '/\*'` matches every source file (every file has a module comment).
- [ ] `/code-review` returns no high-confidence issues.
- [ ] `docs/next-phase.md` exists and names Phase 2.

Run `/verify`. Then open the PR with title `Phase 1: skeleton, PAL, attestation interface, console stubs`. Merge after review. Run `/save-session`.

---

# Phase 2 — Rust server workspace

**Objective.** Cargo workspace under `server/` with four crates (`telemetry`, `ban-engine`, `license-server`, `api`). Tokio + axum, `/healthz` routes, `ort` dependency wired (no model yet), `thiserror` error types, no `unwrap()` outside tests. `server/api/data-categories.md` and the GDPR-17 deletion route stub. Per-crate integration tests. `/verify` builds and tests all crates.

**Owner model.** Sonnet 4.6.
**Branch.** `phase-2-server`.
**One PR.**
**Pre-req.** Phase 0 Rust install. Phase 1 merged.

## Step 2.0 — Rust toolchain pin + workspace skeleton

**Self-contained context brief.** A new agent should know: rust toolchain is installed via rustup; this step creates `rust-toolchain.toml` pinning to a specific stable (use the latest stable at the time the step runs; record the version chosen). The workspace lives under `server/` so it does not pollute the C++ root. Workspace `Cargo.toml` lists four members.

**Tasks.**
- `rust-toolchain.toml` pinning **`channel = "1.83.0"`** with `components = ["clippy", "rustfmt"]`. Reproducibility is a hard requirement for a security product — no floating channel.
- `server/Cargo.toml` workspace with `members = ["telemetry", "ban-engine", "license-server", "api"]` and `[workspace.dependencies]` block pinning `tokio`, `axum`, `tower`, `serde`, `serde_json`, `thiserror`, `tracing`, `tracing-subscriber`, `ort`, `anyhow` (only for `main`-level error reporting, never library code per rust-patterns skill).
- `server/.cargo/config.toml` with profile defaults.
- Top-level `CMakeLists.txt` does **not** build the Rust workspace; document that explicitly. Server build is `cargo build --release` from `server/`.

**Verification.** `cd server && cargo check --workspace` succeeds.

**Exit criteria.** `cargo metadata` shows the four crates.

**Rollback.** Delete `server/`, `rust-toolchain.toml`.

## Step 2.1 — `api` crate: axum app, `/healthz`, error type, server bootstrap

**Self-contained context brief.** A new agent should read CLAUDE.md directive #8 and the rust-patterns skill (Library Errors with `thiserror`, Application Errors with `anyhow`). The `api` crate is the binary entrypoint. It composes routers from `telemetry`, `ban-engine`, `license-server`. It owns the `tokio` runtime and the `tracing` subscriber. Its error type uses `thiserror`; only `main` may use `anyhow`. No `unwrap()` outside tests.

**Tasks.**
- `server/api/src/main.rs` — `tokio::main`, sets up `tracing-subscriber`, builds `Router`, binds to `0.0.0.0:8080` (configurable via env).
- `server/api/src/error.rs` — `#[derive(thiserror::Error, Debug)] enum ApiError { ... }`. `IntoResponse` impl mapping each variant to a status code.
- `server/api/src/routes/healthz.rs` — `GET /healthz` returns `{"status":"ok"}`.
- `server/api/src/routes/mod.rs` — mounts healthz.
- Integration test `server/api/tests/healthz.rs`. Use the `axum-test` workspace dependency (pin a current version), or fall back to `tower::ServiceExt::oneshot` if the agent prefers a zero-dep approach. Do **not** reference `axum::test::TestServer` — that type does not exist in upstream axum.

**Verification.** `cargo test -p api`.

**Exit criteria.** `/healthz` is the canonical liveness route; future routes mount the same way.

**Rollback.** `git restore` the api crate.

## Step 2.2 — `telemetry` crate: ingest skeleton + `ort` wired

**Self-contained context brief.** A new agent should know: telemetry is the high-volume ingest path (per-tick player state, aim deltas, input events). For Phase 2 it is a route stub that accepts a `POST /api/telemetry` JSON body, validates the schema, and drops it on the floor (logged, not stored). The `ort` crate is added as a dependency to confirm it compiles on the target host; no model is loaded yet.

**Tasks.**
- `server/telemetry/Cargo.toml` with `ort = { workspace = true, features = [...] }` (cpu provider only for now; CUDA/CoreML deferred).
- `server/telemetry/src/lib.rs` — `pub fn router() -> axum::Router` exposing `POST /api/telemetry`.
- `server/telemetry/src/schema.rs` — `serde::Deserialize` struct describing the per-tick payload (player id, tick, aim_delta_x/y, input_state bitmask, server_received_ts).
- `server/telemetry/src/error.rs` — `thiserror` error type.
- Integration test `server/telemetry/tests/ingest.rs` posts a valid payload and asserts 202 Accepted; posts an invalid payload and asserts 400.
- `api` mounts `telemetry::router()` under `/api`.

**Verification.** `cargo test -p telemetry`. Confirm `ort` builds (this is the riskiest dependency on first install — record any platform-specific build flags in `docs/next-phase.md`).

**Exit criteria.** Telemetry route is hot-pluggable for the real ingest path.

**Rollback.** Drop the crate from the workspace; remove the mount in api.

## Step 2.3 — `ban-engine` crate: rule cache + signed-bundle deserializer skeleton

**Self-contained context brief.** A new agent should know: ban authority lives on the server (Locked Decision and CLAUDE.md). Detection rules are server-pushed signed bundles, rotated weekly, with a short-lived local cache. Phase 2 lays the structures and routes; the actual signature verification (Ed25519) and rule evaluation lands in a later phase under `/tdd`.

**Tasks.**
- `server/ban-engine/src/lib.rs` — `pub fn router() -> Router` exposing `GET /api/rules/current` (returns the active rule bundle metadata: version, sha256, signed-by, expires-at — initially hard-coded placeholder).
- `server/ban-engine/src/bundle.rs` — `struct RuleBundle { ... }` with `serde` derive. Deserializer rejects bundles without a signature field. The verification path is a placeholder, BUT the placeholder fails-closed: a `must_verify: bool` field on the bundle loader defaults to `true`. In `cfg(not(debug_assertions))` builds (i.e., `--release`), the placeholder verifier panics on construction so a release binary cannot accept unverified bundles. A `#[cfg(feature = "unverified_bundles_dev_only")]` feature gate is the only way to compile the placeholder; CI rejects this feature on release branches.
- `server/ban-engine/src/error.rs` — `thiserror`.
- Integration test asserting `GET /api/rules/current` returns the placeholder bundle in dev mode and that a release build refuses to compile without the dev-only feature gate.

**Verification.** `cargo test -p ban-engine`.

**Exit criteria.** Bundle struct shape settled; signature wire-format documented in `docs/rule-bundle-format.md`.

## Step 2.4 — `license-server` crate: issue / revoke / verify route stubs

**Self-contained context brief.** Per Locked Decision #5, DRM is licence-bound and TPM-sealed. The `license-server` crate exposes the licence lifecycle surface to the client. Phase 2 stubs the routes and persists nothing (in-memory for tests).

**Tasks.**
- `server/license-server/src/lib.rs` — `pub fn router() -> Router` exposing `POST /api/license/issue`, `POST /api/license/revoke`, `POST /api/license/verify`.
- Each route deserializes a typed request, returns a typed response, and at this phase returns `501 Not Implemented` with a typed body explaining the route is reserved.
- Integration tests covering each route's 501 contract — when implementation lands, these flip to real assertions.

**Verification.** `cargo test -p license-server`.

**Exit criteria.** Licence routes are reserved; clients can compile against the URL surface.

## Step 2.5 — `server/api/data-categories.md` + GDPR-17 deletion route

**Self-contained context brief.** Legal floor (CLAUDE.md). EU shipment requires a documented data-collection notice and a GDPR Article 17 deletion route with 30-day SLA. **Phase 2 must NOT promise a 30-day SLA the persistence layer cannot honor.** A 202 from an in-memory store is worse than no route — restart loses the request, but the user has been told "queued, 30 days." The Phase 2 stub returns `503 Service Unavailable` with `Retry-After: 86400` and a body `{"status":"unavailable","reason":"deletion service not yet provisioned"}`. The route is wired and reachable so clients can compile against the URL surface; the contract flips to 202 in a follow-up phase that lands a durable persistence layer (Postgres or SQLite) and the deletion worker under `/tdd`.

**Tasks.**
- `server/api/data-categories.md` listing every category collected at scaffold time: process info, module info, telemetry stream, hardware identifiers (TPM EK, platform identifiers). Each entry has: field name, source, retention default, legal basis, operator-of-record.
- `server/api/src/routes/account.rs` — `DELETE /api/account/{id}/data`. Validates id, returns `503` with `Retry-After: 86400` and the unavailable-body documented above. Logs the request via `tracing` (not as a "queued" promise — purely as observability).
- Integration test asserts the 503 contract and the `Retry-After` header.
- Reviewer note in CLAUDE.md: any new telemetry field must update `data-categories.md` in the same PR.
- `docs/gdpr-17-rollout.md` — names the follow-up phase that lands the durable store and flips the contract to 202.

**Verification.** `cargo test -p api`. `data-categories.md` lints clean.

**Exit criteria.** EU-shipment legal floor is structurally present. (Real deletion logic is a follow-up phase merge gate.)

## Step 2.6 — Workspace verification gate

- [ ] `cd server && cargo build --workspace --release`
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `rg -n '\.unwrap\(\)' server/ -g '!*test*' -g '!tests/*'` returns empty.
- [ ] `/code-review` clean.
- [ ] `docs/next-phase.md` updated for Phase 3 (WDK env, Windows VM, signing strategy).

Run `/verify`. PR title `Phase 2: Rust server workspace + GDPR-17 stub`. Merge. `/save-session`.

---

# Phase 3 — Windows kernel watchdog (KMDF) + SDK wiring

**Objective.** End-to-end Windows KMDF driver with `DriverEntry`, `PsSetCreate*NotifyRoutine`, `ObRegisterCallbacks`, and an IOCTL bridge to userspace. Boot-start service install scripts. SDK C-API (`horkos_init`, `drm_validate`, `ac_start`) and `pc_basic` example. Driver builds against the current WDK; example reports degraded mode without driver, active with it.

**Owner model.** Sonnet 4.6.
**Branch.** `phase-3-win-kernel` (or `phase-3a-win-kernel` + `phase-3b-win-sdk` if split).
**Target.** One PR if achievable in two focused sessions. **Split seam:** if the agent estimates more than two sessions, split into Phase 3a (Steps 3.1–3.4: WDK env + driver skeleton + Notify routines + ObCallbacks) and Phase 3b (Steps 3.5–3.8: IOCTL bridge + service install + SDK + BYOVD skeleton). Record the split in the Mutation log.
**Pre-req.** Windows VM/CI with current WDK. Phase 1 merged. Phase 2 may be parallel — SDK C-API only depends on Phase 1.

**SAFETY GUARD.** All kernel work happens in a snapshot-ready Windows VM. `verifier.exe` is enabled for the driver throughout bring-up. Per CLAUDE.md directive #13, when uncertain about a kernel API, stop and flag it before touching code. Use the safety-guard skill in Careful Mode for the entire phase.

## Step 3.1 — Windows build environment doc + CMake WDK detection

**Self-contained context brief.** A new agent on the Windows VM should know: WDK install location is `C:\Program Files (x86)\Windows Kits\10\` (current as of Windows 11 24H2). KMDF runtime ships with the WDK. CMake needs to detect `WindowsDriverKit_DIR`. The driver project does not link against C++ runtime — KMDF drivers are C-mostly.

**Tasks.**
- `docs/windows-build.md` — VM provisioning, WDK install, test-signing instructions (BCD edit, `bcdedit /set testsigning on`), `verifier.exe` setup for the driver.
- `kernel/win/CMakeLists.txt` — detects WDK, sets up KMDF driver target with the right linker flags and runtime library exclusions.
- Note: this CMake file is **not** included from the root CMakeLists on non-Windows hosts. The root file gates with `if(WIN32) add_subdirectory(kernel/win) endif()`.

**Verification.** On a Windows VM with WDK installed, `cmake -S . -B build` succeeds and detects WDK. On macOS/Linux, the same command succeeds and silently skips the driver target.

**Exit criteria.** Cross-host CMake invocation produces the right targets per host.

## Step 3.2 — KMDF driver skeleton: `DriverEntry`, IRP dispatch, unload

**Self-contained context brief.** A new agent should read CLAUDE.md directives #4, #5, #13 first. KMDF skeleton: `DriverEntry` calls `WdfDriverCreate`, registers an unload callback. The unload tears down everything. The driver creates a control device for IOCTL communication with userspace. All `NTSTATUS` returns are checked. Only safe string functions (`RtlStringCbCopyA` family). No raw `_WIN32` use — already in `kernel/win/` so it's the implementation backend, but still no `_WIN32` macro inside the file.

**Tasks.**
- `kernel/win/src/DriverEntry.c` — `DriverEntry`, `EvtDriverUnload`, control-device creation. Module comment names this as the entrypoint and which interface it implements.
- `kernel/win/src/IrpDispatch.c` — IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_DEVICE_CONTROL stubs. Each completes the IRP with `STATUS_SUCCESS` or a typed error.
- `kernel/win/include/horkos_kernel.h` — internal kernel header (not exposed to userspace).
- INF file `horkos.inf` — boot-start service registration, signing notes.

**Verification.** Driver builds against WDK. `verifier.exe` accepts it. Loaded with `sc.exe create` + `sc.exe start` it does not BSOD on a fresh VM.

**Exit criteria.** Driver loads, unloads cleanly, no leaks per `verifier.exe`.

## Step 3.3 — `PsSetCreate*NotifyRoutine` + `PsSetLoadImageNotifyRoutine`

**Self-contained context brief.** Vanguard-style early-bird visibility: register process create/exit, thread create/exit, and image-load callbacks. Capture each event into a ring buffer. Userspace will drain via IOCTL in Step 3.5. Phase 3 only captures and counts — full evidence collection lands in a later phase under `/tdd`.

**Tasks.**
- `kernel/win/src/Notify.c` — registration in `DriverEntry`, deregistration in unload. Each callback writes a small event struct to a lock-free ring buffer.
- `kernel/win/src/RingBuffer.c` — single-producer-multiple-consumer not needed; SPSC suffices since IOCTL handler is the only consumer. Use `KeAcquireSpinLockAtDpcLevel` correctly. If uncertain about IRQL, **stop and flag**.
- Counter exposed via the IOCTL skeleton.

**Verification.** Spawn a process under the driver-loaded VM; the counter increments. Driver-verifier-clean.

**Exit criteria.** Process / thread / image load events flow into a kernel-side buffer.

## Step 3.4 — `ObRegisterCallbacks` for handle filtering

**Self-contained context brief.** ObRegisterCallbacks lets the driver inspect (and optionally strip rights from) handles opened to the protected process. Phase 3 registers the callback and logs each filter decision; it does not yet strip any rights — that decision lands under `/tdd` with bypass tests in Phase 5.

**Tasks.**
- `kernel/win/src/Callbacks.c` — `ObRegisterCallbacks` registration with `OB_OPERATION_HANDLE_CREATE` and `OB_OPERATION_HANDLE_DUPLICATE` for `PsProcessType` and `PsThreadType`. Pre-callback returns `OB_PREOP_SUCCESS` after logging; rights stripping is gated behind a config flag default-off.
- Deregister on unload.

**Verification.** Open a handle to the protected process from a test userland program; the kernel log shows the filter event.

**Exit criteria.** Callback registered, observable, default-passive.

## Step 3.5 — IOCTL bridge to userspace

**Self-contained context brief.** Userspace consumes events via `DeviceIoControl`. Define a small set of IOCTL codes (drain events, get status, push policy). The shared header is C99, fully self-contained, and includable from kernel TUs *and* userspace TUs — but never the same translation unit per CLAUDE.md directive #4. The header uses **only `<stdint.h>` fixed-width types (`uint32_t`, `uint64_t`)**, never the Windows-cased aliases (`UINT32`). It includes no platform headers (`<windows.h>`, `<wdm.h>`, `<linux/types.h>` all forbidden). Reuse the event payload types from `sdk/include/horkos/event_schema.h` (Phase 1 Step 1.6) — do not redefine them here.

**Tasks.**
- `sdk/include/horkos/ioctl.h` — `#include "horkos/event_schema.h"`. Defines IOCTL codes (`HK_IOCTL_DRAIN_EVENTS`, `HK_IOCTL_GET_STATUS`, `HK_IOCTL_PUSH_POLICY`), DRAIN buffer envelope. Fixed-width fields only.
- A kernel TU and a userspace TU each `#include` the header and contain a `static_assert(sizeof(...) == ...)` block that pins the wire-format sizes. Drift breaks the build.
- Kernel side: `kernel/win/src/IrpDispatch.c` handles each code.
- Userspace test: `tests/integration/win/ioctl_smoke.cpp` opens the device, sends each IOCTL, asserts return. Lives in `tests/integration/`, never under `kernel/`, to enforce the kernel-vs-userspace TU split visually.

**Verification.** Smoke test passes against a loaded driver.

**Exit criteria.** Userspace ↔ kernel surface settled.

## Step 3.6 — Boot-start service install scripts + test-signing docs

**Tasks.**
- `kernel/win/install/install.ps1` — uses `sc.exe create horkos type= kernel start= boot binPath= ...`.
- `kernel/win/install/uninstall.ps1`.
- `docs/windows-signing.md` — test-signing flow vs production EV cert flow. **Production signing requires a real EV certificate; this repo never bypasses signing.**

## Step 3.7 — SDK C-API + `pc_basic` example

**Self-contained context brief.** SDK is the public surface a game integrates. Phase 3 lands `horkos_init`, `drm_validate`, `ac_start`, all C, all stable across versions. Example `pc_basic` calls all three and reports degraded vs active mode based on whether the driver is loaded.

**Tasks.**
- `sdk/include/horkos/sdk.h` — C API.
- `sdk/src/sdk.cpp` — implementation that delegates to `drm/`, `ac/`, and detects driver presence via `OpenSCManager` + `EnumServicesStatus`.
- `examples/pc_basic/main.cpp` — calls each function, prints status.
- CMake: `add_executable(pc_basic ...)` linked against the SDK.

**Verification.** Run on Windows with driver loaded → reports active. Run without → reports degraded. Both must not crash.

## Step 3.8 — Driver whitelist enforcement skeleton (BYOVD)

**Self-contained context brief.** A signed bundle of known-vulnerable driver hashes is the BYOVD blocklist. Phase 3 lands the data structure and the enforcement hook in `PsSetLoadImageNotifyRoutine`; the actual list is fetched from the server in a later phase. For Phase 3, the list is empty + a TODO referencing the rule-bundle plumbing in Phase 2.

**Tasks.**
- `kernel/win/src/Whitelist.c` — image-load callback consults the whitelist, blocks load if matched.
- Bypass-test fixture is a **self-built deliberately-vulnerable test driver** signed for test-mode boot, never a real BYOVD entry from `loldrivers.io`. Repo never commits a real BYOVD binary; the bypass test builds its fixture as part of the test pipeline. Phase 3 lands the build target stub; the actual fixture and enforcement lands in Phase 5.
- `bypass-tests/win/byovd_load.cpp` — attempts to load the test-fixture driver and asserts `ac_get_last_flag()` returns the BYOVD flag. Marked `[disabled]` for Phase 3 (real enforcement lands in Phase 5).

**Exit criteria.** Hook in place; data plumbing referenced.

## Phase 3 verification gate

- [ ] Driver builds against current WDK (Windows VM).
- [ ] `verifier.exe` reports clean for the loaded driver under load.
- [ ] `pc_basic` runs both with and without the driver and reports the right mode.
- [ ] All NTSTATUS checked: `rg -n '(NtStatus|NTSTATUS)' kernel/win/ | grep -v 'NT_SUCCESS\|status =\|status ==' ` shows no unchecked uses.
- [ ] Safe string functions only: `rg -n '(strcpy|strcat|sprintf)\b' kernel/win/` returns empty.
- [ ] `/code-review` clean.
- [ ] `docs/next-phase.md` updated for Phase 4.

Run `/verify`. PR title `Phase 3: Windows KMDF watchdog + SDK + pc_basic example`. Merge. `/save-session`.

---

# Phase 4 — Linux eBPF + macOS userspace daemon (+ ES target gated)

**Objective.** Linux eBPF programs (LSM + tracepoints + uprobes) primary, LKM behind `HORKOS_LINUX_LKM` build flag. macOS userspace daemon as the bring-up path; SystemExtension + EndpointSecurity client target gated by `HORKOS_MACOS_ES`. DMA detection backends (PCIe enumeration + IOMMU state) on Win + Linux with the UEFI-firmware caveat documented.

**Owner model.** Sonnet 4.6.
**Branch.** `phase-4-linux-macos`.
**One PR.**
**Pre-req.** Phase 3 SDK surface stable. Linux CI image with `clang-19`, `libbpf-dev`, `bpftool`, `tpm2-tss-dev`. macOS host for daemon work.

## Step 4.1 — Linux eBPF skeleton: build target, libbpf, LSM hook stub

**Self-contained context brief.** A new agent should know: eBPF programs live under `kernel/linux/bpf/`, written in restricted C, compiled with `clang -target bpf`. Userspace loader uses `libbpf` with CO-RE. LSM hooks are `lsm/file_open`, `lsm/task_alloc`, `lsm/bprm_check_security` for early process-create visibility. CO-RE means one `.bpf.o` ships and works across kernel versions.

**Tasks.**
- `kernel/linux/bpf/CMakeLists.txt` — invokes `clang -target bpf -O2 -g -c` for each `*.bpf.c`; runs `bpftool gen skeleton` to produce `*.skel.h`.
- `kernel/linux/bpf/src/lsm_file_open.bpf.c` — LSM hook, logs PID + filename to a ring buffer. CO-RE annotations (`BPF_CORE_READ`).
- `kernel/linux/userspace/Loader.cpp` — opens skeletons, attaches programs, polls ring buffer, dispatches into the SDK event sink.

**Verification.** On Ubuntu CI runner with `bpftool` and a recent kernel, the loader attaches and observes events from a test process.

**Exit criteria.** eBPF program loads, attaches, ring-buffer drains.

## Step 4.2 — Linux uprobes + tracepoints

**Tasks.**
- Tracepoints: `tracepoint/syscalls/sys_enter_ptrace`, `tracepoint/sched/sched_process_exec`.
- Uprobe shim: dynamic registration on the protected game binary's anti-debug check function (placeholder address).

## Step 4.3 — Linux LKM behind `HORKOS_LINUX_LKM` build flag

**Self-contained context brief.** Some self-hosted server operators and non-Deck distros prefer (or only support) LKM. Land the LKM behind a build flag, not in the Steam Deck shipping path.

**Tasks.**
- `kernel/linux/lkm/Makefile` — out-of-tree kernel module Makefile.
- `kernel/linux/lkm/horkos.c` — module init/exit, security_hook registration where the kernel allows it.
- CMake: `option(HORKOS_LINUX_LKM "Build the Linux LKM (non-Deck path)" OFF)`.

**Verification.** `make -C kernel/linux/lkm` succeeds against a kernel-headers install. Module loads on a non-Deck Linux VM with `insmod`.

## Step 4.4 — macOS launchd daemon + XPC service skeleton

**Self-contained context brief.** Per Locked Decision #4, until Apple grants the EndpointSecurity entitlement, the bring-up path is a userspace daemon. It runs as launchd job, communicates with the SDK via XPC.

**Tasks.**
- `daemon/macos/horkosd.cpp` — launchd-managed daemon main.
- `daemon/macos/com.horkos.daemon.plist` — launchd plist.
- XPC service skeleton.

**Verification.** `launchctl load` succeeds; daemon responds to a test XPC ping.

## Step 4.5 — macOS EndpointSecurity client gated on `HORKOS_MACOS_ES`

**Self-contained context brief.** Read CLAUDE.md directive #7 first: ES events must always be replied to. The ES client subscribes to `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_AUTH_EXEC`, etc. Auth-mode events MUST receive a reply within the OS-imposed deadline; dropping one hangs the system.

**Tasks.**
- `kernel/macos/es/EsClient.mm` — Objective-C++ ES client, replies to every auth event with `ES_AUTH_RESULT_ALLOW` initially (Phase 4 is observation-only).
- CMake: `option(HORKOS_MACOS_ES "Build the EndpointSecurity SystemExtension target" OFF)`.
- A second flag `option(HORKOS_MACOS_ES_PROVISIONED "Embed the endpoint-security entitlement in Info.plist (requires Apple approval + provisioning profile)" OFF)`. The `Info.plist` only includes `com.apple.developer.endpoint-security.client` when this flag is on. Default `HORKOS_MACOS_ES=ON` builds without provisioning still load on a dev machine because the entitlement is absent. Document this in `docs/macos-es.md`.

**Verification.** Builds with `HORKOS_MACOS_ES=ON`. Approval to run is out of scope this PR.

## Step 4.6 — DMA detection: PCIe enumeration + IOMMU state

**Self-contained context brief.** The 2025 UEFI/IOMMU CVE class shows firmware can lie about IOMMU state. Detect-and-report only; cross-check with PCIe enumeration. Never trust firmware's claim alone (CLAUDE.md scope statement on DMA).

**Tasks.**
- `dma_detect/include/horkos/dma_detect.h` — interface.
- `dma_detect/backends/win/PcieEnumWin.cpp` — enumerates PCIe devices via SetupAPI, queries DMA-capable devices, reads IOMMU/VT-d state via `Get-CimInstance` proxied through the driver.
- `dma_detect/backends/linux/PcieEnumLinux.cpp` — reads `/sys/bus/pci/devices/*/iommu_group/`, `/sys/class/iommu/`.
- `docs/dma-detection.md` — UEFI firmware caveat written explicitly: "If a firmware reports IOMMU on but PCIe enumeration suggests otherwise, flag at high confidence and let the server decide."

**Exit criteria.** DMA detection lands a server-side flag; no client-side ban action.

## Phase 4 verification gate

- [ ] Linux: `clang-19 -target bpf -O2 -c kernel/linux/bpf/src/*.bpf.c` succeeds; userspace loader test passes against a CI Linux runner.
- [ ] macOS: daemon builds and `launchctl load`s; ES target builds with `HORKOS_MACOS_ES=ON`.
- [ ] DMA detection backends compile on each platform; the doc names the UEFI caveat.
- [ ] `bypass-tests/linux/ptrace_attach.cpp` and `bypass-tests/macos/dylib_inject.cpp` are present (may be `[disabled]` until Phase 5 enforcement).
- [ ] `/code-review` clean.
- [ ] `docs/next-phase.md` updated for Phase 5.

Run `/verify` per platform. PR title `Phase 4: Linux eBPF + macOS daemon + DMA detection`. Merge. `/save-session`.

---

# Phase 5 — LLVM 19 passes + console stubs + bypass-tests + final review

**Objective.** Standalone LLVM-19 obfuscation tool implementing `ControlFlowFlattening`, `OpaquePredicates`, `StringEncryption`. Per-function opt-in via `__attribute__((annotate("hk_obfuscate")))`. Pass test harness via `lit` + `FileCheck`. Console folders fleshed with public-doc-shaped stubs. `bypass-tests/` populated with one representative test per PC platform: BYOVD, ptrace, dylib injection. Final `/code-review` + `/verify` across the full PC matrix.

**Owner model.** Sonnet 4.6.
**Branch.** `phase-5-llvm-bypass-final` (or `phase-5a-llvm` + `phase-5b-bypass-console-final` if split).
**Target.** One PR if achievable in two focused sessions. **Split seam:** Phase 5a (Steps 5.1–5.5: obfuscator tool + three passes + lit/FileCheck harness) and Phase 5b (Steps 5.6–5.9: console fleshout + bypass tests + final review + ship-readiness doc). Record the split in the Mutation log.
**Pre-req.** `llvm@19` installed (Phase 0 prerequisite). All previous phases merged.

## Step 5.1 — LLVM 19 detection + pass-plugin build target

**Tasks.**
- `obfuscator/CMakeLists.txt` — finds LLVM 19 via `find_package(LLVM 19 REQUIRED CONFIG)`, builds `hk_obfuscator` as a standalone tool that invokes the new pass manager with our passes.
- `obfuscator/src/Plugin.cpp` — registers the three passes with the new PM.
- The tool is **never shipped to end users**; it is a build-time tool only. Document this in `obfuscator/README.md`.

## Step 5.2 — `ControlFlowFlattening` pass + per-function attribute opt-in

**Self-contained context brief.** Read CLAUDE.md directive #9 first. The pass must opt-in via `__attribute__((annotate("hk_obfuscate")))`. The GAME binary's hot-loop functions never carry the annotation. The AC binary may apply globally (or via a sweeping CLI flag) since perf is allowed to be heavy there. **LLVM gotcha:** Clang lowers function-level `__attribute__((annotate(...)))` into the module-level global `@llvm.global.annotations` (a `[N x { i8*, i8*, i8*, i32, i8* }]` array), NOT into a function attribute the new pass manager can read directly. The pass therefore walks `@llvm.global.annotations` at module-load time, builds a set of `Function*` whose annotation matches `"hk_obfuscate"`, and only mutates those. A pass that queries function attributes for the annotation will silently no-op against valid input — and the `lit` test will pass against that no-op.

**Tasks.**
- `obfuscator/src/passes/ControlFlowFlattening.cpp` — function pass under a module pass that pre-populates the annotated-functions set from `@llvm.global.annotations`. Skips functions not in the set when running in opt-in mode. Flattens control flow via dispatcher block.
- `obfuscator/test/cff/basic.ll` — LLVM IR fixture **regenerated by the pinned `llvm@19` clang** (`/opt/homebrew/opt/llvm@19/bin/clang -emit-llvm -S ...`). Document the regeneration command in `obfuscator/test/README.md`. IR text format drifts between major LLVM versions — pinning the regeneration toolchain is non-negotiable.
- `obfuscator/test/cff/basic.test` — `lit` test using `FileCheck` to assert (a) the dispatcher block exists, (b) the original CFG is collapsed, AND (c) a *non-annotated* function in the same module is *unchanged* (this last assertion catches the silent no-op case described above).

**Verification.** `lit obfuscator/test/cff/` passes.

## Step 5.3 — `OpaquePredicates` pass

**Tasks.** As 5.2, for opaque predicates. Each branch test gets an `(x*x*x - x) % 6 == 0`-style invariant inserted with the always-true side guarded.

## Step 5.4 — `StringEncryption` pass

**Tasks.** As 5.2, for string literals. Compile-time encrypts globals tagged for obfuscation; emits a per-translation-unit `__attribute__((constructor))` that decrypts at load.

## Step 5.5 — `lit` + `FileCheck` harness

**Tasks.**
- `obfuscator/test/lit.cfg` — discovers tests in subfolders.
- CI step: `lit obfuscator/test/`.
- Hook into `/verify`.

## Step 5.6 — Console stub fleshout (GDK only this phase; Nintendo / PlayStation stay README-only)

**Self-contained context brief.** Locked Decision #7 + CLAUDE.md directive #2. Console SDK headers are not in the repo. **GDK is partially public via `learn.microsoft.com`; Nintendo and PlayStation docs are NDA-only.** Phase 5 fleshes only the GDK stubs from public Microsoft docs; Nintendo and PlayStation stay as `README.md` plus a single `// TODO: signatures land under NDA in a separately-gated phase` placeholder `.cpp` per platform. No proprietary headers, no NDA-derived signatures.

**Tasks.**
- `console/gdk_xbox/stubs/horkos_gdk.cpp` — function signatures matching the public GDK XGameRuntime / XUser API surface (cite the `learn.microsoft.com` page in the module comment per signature). Each stub returns `HK_NOT_AVAILABLE`. Excluded from the default build.
- `console/nintendo_switch/stubs/horkos_nintendo.cpp` — single `// TODO: signatures land under NDA. README describes the public-doc shape only.` placeholder body.
- `console/playstation/stubs/horkos_ps.cpp` — same.
- Each `.cpp` excluded from the default build via CMake.

## Step 5.7 — `bypass-tests/` populated with one representative test per PC platform

**Self-contained context brief.** CLAUDE.md directive #12 makes bypass-tests a merge gate. Phase 5 lands the first representative test per platform; future security-touching PRs add more. Each test exercises a real defeat technique and asserts the AC stack reports a flag (it does not assert a ban — bans are server-side).

**Tasks.**
- `bypass-tests/win/byovd_load.cpp` — attempts to load a known-bad driver from the BYOVD list; asserts `ac_get_last_flag()` returns the BYOVD flag.
- `bypass-tests/linux/ptrace_attach.cpp` — `ptrace(PTRACE_ATTACH, target, ...)`; asserts the ptrace flag fires via the eBPF hook.
- `bypass-tests/macos/dylib_inject.cpp` — `DYLD_INSERT_LIBRARIES`; asserts the daemon reports the injection flag.
- Each test enables on the target platform via CMake `if()` guards.
- A merge-time CI job runs the matching test on each platform.

**Verification.** Each test runs on its target platform and asserts a flag is raised.

**Exit criteria.** Merge gate operational.

## Step 5.8 — Final cross-repo `/code-review` and `/verify`

**Tasks.** Run `/code-review` against the full repo. Address any high-confidence issues. Run `/verify` on each PC platform reachable from CI. Run `cargo audit` and `cargo deny check` on the Rust workspace. Confirm `data-categories.md` matches every field actually emitted by the telemetry route.

**Exit criteria.** Zero high-confidence issues. Every platform's `/verify` green.

## Step 5.9 — `docs/ship-readiness.md`

**Tasks.** Replace `docs/next-phase.md` with `docs/ship-readiness.md` listing what is left for production: real signing certificate, ES entitlement approval, console SDK access, BYOVD ingestion, signed rule bundle pipeline, ML model training and inference path, GDPR-17 deletion logic.

---

## Reviewer checklist (used by the adversarial review subagent)

- Does every new file have a module comment naming role + target platforms + interface?
- Does any source outside `platform/platform.h` reference `_WIN32` / `__linux__` / `__APPLE__` directly?
- Does any source outside `platform/` or a `backends/` folder call a platform API directly?
- Are kernel and userspace code in separate translation units?
- Are all `NTSTATUS` returns checked?
- Do kernel C files use only safe string functions?
- Does the macOS ES path always reply to auth events?
- Is the server fully async on tokio with no blocking calls on async threads?
- Does any non-test code use `unwrap()`?
- Do telemetry field changes update `data-categories.md` in the same PR?
- Are bypass-test additions present for security-folder changes?
- Are any proprietary SDK headers committed?
- Are LLVM passes restricted to attribute-annotated functions on the GAME binary?
- Are Locked Decisions touched? If yes, is there a Mutation log entry?

---

## Anti-pattern catalog

- "Just write it as a one-liner with `_WIN32`" — rejected, route through `platform.h`.
- "I'll add the unwrap and clean it up later" — rejected, clean it up now.
- "I'll silence the kernel warning with `-w`" — rejected, fix the warning.
- "I'll skip the bypass test for this folder, it's small" — rejected, merge gate.
- "I'll commit the SDK header, it's only public API" — rejected, console SDKs are proprietary even for public-named symbols. Stubs only.
- "I'll add `unsafe` here so the borrow checker stops complaining" — rejected, fix the borrow.
- "I'll ship the obfuscator alongside the AC client to avoid build-time setup" — rejected, build tool only.
- "I'll bypass test-signing with `--no-verify`" — rejected, real signing certificate procurement is the path.

---

## Mutation log

(empty — record entries here as `## YYYY-MM-DD <commit-sha>: <one-line summary>` followed by rationale and Locked-Decision impact)
