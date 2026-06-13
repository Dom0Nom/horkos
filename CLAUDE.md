# Horkos — Cross-cutting Guardrails

These rules are binding on every agent executing any phase of this project.
They apply from turn 1. Failing to follow them is a failure of the response.

---

## Read this first

**`docs/ARCHITECTURE.md` is the codebase orientation file — read it before
touching code in an unfamiliar area.** It covers the directory map, the two
wire planes and data flow (client sensors → telemetry analyzers → ban-engine
fusion), the eight defensive design principles (no single-signal bans,
structural FP gating, fail-closed ingest, honest `HK-UNCERTAIN` stubs), the
build/verify matrix (what compiles on this macOS
host vs. needs the Windows box or a Linux target), and the source-of-truth
doc index. Keep it current: structural changes (new top-level dir, new wire
plane, changed verify matrix) update `docs/ARCHITECTURE.md` in the same PR.

---

## Cross-cutting guardrails

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
12. **When uncertain about a kernel API, stop and flag it.** A BSOD is worse than a delay.
13. **No business logic in scaffolding sessions.** Stubs and module comments only. Logic lands in subsequent phases under `/tdd` where testable.

---

## Locked decisions

1. **Server stack:** Rust + axum + tokio + ONNX Runtime via the `ort` crate. Chosen for tail-latency determinism in the ban path.
2. **Windows kernel:** KMDF (not WDM). Boot-start service. Driver whitelist enforced (BYOVD defense).
3. **Linux kernel:** eBPF (LSM + tracepoints + uprobes) primary; LKM behind a build flag for self-hosted servers and non-Deck distros. Steam Deck Game Mode requires eBPF.
4. **macOS kernel:** System Extension + EndpointSecurity gated on Apple entitlement approval. Userspace daemon ships as bring-up path; SysExt swap when entitlement lands.
5. **LLVM toolchain:** LLVM 19. Heavy obfuscation across the AC binary; light, attribute-opt-in obfuscation on GAME init/licence/integrity/attestation paths only. Standalone build tool, never shipped.
6. **Attestation:** `tpm2-tss` for Windows + Linux behind a single `Attestation` C++ interface; CryptoKit / Secure Enclave on macOS; documented stubs for console SDKs.
7. **Console SDKs (NintendoSDK, GDK, PlayStation):** proprietary, not present. Stubs only with public-doc-shaped signatures, every stub commented with the documented function it maps to.

---

## On uncertainty

If you are uncertain about a kernel API, an ES auth flow, a signing requirement, or any security-critical behaviour: **stop and flag it to the user before touching any code.**

Do not guess on:
- Windows kernel APIs (IRQL, IRP lifecycle, ObRegisterCallbacks semantics)
- macOS EndpointSecurity auth-mode event reply deadlines
- Code-signing requirements (EV cert, WHQL, test-signing vs production)
- Any claim about detection efficacy or bypass resistance

A BSOD in a developer VM is recoverable. A mis-documented security interface is not.
